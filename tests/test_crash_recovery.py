"""Crash recovery and lost acknowledgments (DoD #6; SEC-014/024).

These use real process termination (SIGKILL, uncatchable) at explicit
transaction boundaries, then restart a fresh owner on the same durable stores
and check the recovery behavior. Scope note: this exercises the local
transactional resource (SQLite). An external, non-transactional effect would
need its own recovery guarantee; that is what the UNKNOWN outcome is for, and
scenario 4 below covers it.

Boundaries (set via the owner's crash_hook):
  before_transaction  -> nothing written
  mid_transaction     -> effect written but not committed
  after_commit        -> effect + receipt committed, freshness not yet advanced
"""

from __future__ import annotations

import json
import os
import signal
import sqlite3
import tempfile
import threading
import unittest

from vgi.crypto import KeyPair
from vgi.execution.freshness import FreshnessAuthority
from vgi.execution.outcomes import ConfirmationUnavailable, OutcomeResolver
from vgi.execution.resource_owner import AuthorizationError, ResourceOwner
from vgi.governance.grants import GrantAuthority
from vgi.governance.policy import default_config_policy
from vgi.intelligence.proposer import Proposer

HAS_FORK = hasattr(os, "fork")


@unittest.skipUnless(HAS_FORK, "requires os.fork for real process-termination tests")
class CrashRecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp(prefix="vgi-crash-")
        self.resource_db = os.path.join(self.workdir, "resource.db")
        self.fresh_db = os.path.join(self.workdir, "freshness.db")
        self.executor_key = KeyPair.generate()
        self.authority_key = KeyPair.generate()

        issue_fresh = FreshnessAuthority(self.fresh_db)
        authority = GrantAuthority(self.authority_key, default_config_policy(), issue_fresh)
        self.proposal = Proposer().propose_config_change("log.level", "debug")
        self.grant = authority.issue(self.proposal)
        issue_fresh.close()
        self.request = {"effect": self.proposal.effect, "grant_token": self.grant.to_dict()}

    def _owner(self, crash_hook=None) -> ResourceOwner:
        return ResourceOwner(
            self.resource_db,
            executor_key=self.executor_key,
            authority_verify_key=self.authority_key.verify_key,
            freshness=FreshnessAuthority(self.fresh_db),
            crash_hook=crash_hook,
        )

    def _redeem_then_crash_at(self, boundary: str) -> int:
        """Fork a child that redeems with a SIGKILL hook at `boundary`. Returns
        the child's wait-status."""
        pid = os.fork()
        if pid == 0:  # child
            def hook(b: str) -> None:
                if b == boundary:
                    os.kill(os.getpid(), signal.SIGKILL)

            try:
                owner = self._owner(crash_hook=hook)
                owner.redeem_and_apply(self.request)
                os._exit(0)  # survived without crashing
            except BaseException:
                os._exit(2)
        _, status = os.waitpid(pid, 0)
        return status

    def _stored_receipt_id(self):
        conn = sqlite3.connect(self.resource_db, timeout=30)
        try:
            row = conn.execute(
                "SELECT receipt_json FROM redemptions WHERE grant_id = ?",
                (self.grant.grant["grant_id"],),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return json.loads(row[0])["receipt"]["receipt_id"]

    def _current_value(self):
        owner = self._owner()
        v = owner.current_value("log.level")
        owner.close()
        return v

    def _assert_killed(self, status: int) -> None:
        self.assertTrue(os.WIFSIGNALED(status), f"child did not die by signal: {status}")
        self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)

    # -- scenario 1 ---------------------------------------------------------

    def test_crash_before_transaction_leaves_nothing(self) -> None:
        status = self._redeem_then_crash_at("before_transaction")
        self._assert_killed(status)
        self.assertIsNone(self._stored_receipt_id())
        self.assertIsNone(self._current_value())
        # Recovery + retry completes the operation exactly once.
        owner = self._owner()
        receipt = owner.redeem_and_apply(self.request)
        self.assertEqual(receipt.receipt["outcome"], "applied")
        self.assertEqual(owner.current_value("log.level"), "debug")
        owner.close()

    # -- scenario 2 ---------------------------------------------------------

    def test_crash_mid_transaction_leaves_no_partial_effect(self) -> None:
        status = self._redeem_then_crash_at("mid_transaction")
        self._assert_killed(status)
        # No committed receipt and no partial effect.
        self.assertIsNone(self._stored_receipt_id())
        self.assertIsNone(self._current_value())
        # Retry completes cleanly.
        owner = self._owner()
        receipt = owner.redeem_and_apply(self.request)
        self.assertEqual(receipt.receipt["outcome"], "applied")
        self.assertEqual(owner.current_value("log.level"), "debug")
        owner.close()

    # -- scenario 3 ---------------------------------------------------------

    def test_crash_after_commit_retry_returns_original_receipt(self) -> None:
        status = self._redeem_then_crash_at("after_commit")
        self._assert_killed(status)
        # The effect + receipt are durable even though the ack never came.
        original_rid = self._stored_receipt_id()
        self.assertIsNotNone(original_rid)
        self.assertEqual(self._current_value(), "debug")

        # Restart (recover() reconciles freshness) and retry: same receipt, no
        # re-application.
        owner = self._owner()
        retry = owner.redeem_and_apply(self.request)
        self.assertEqual(retry.receipt["receipt_id"], original_rid)
        self.assertEqual(retry.receipt["outcome"], "applied")
        self.assertEqual(owner.current_value("log.level"), "debug")
        owner.close()
        self._assert_single_redemption()

    # -- scenario 5 ---------------------------------------------------------

    def test_concurrent_retries_after_restart_apply_once(self) -> None:
        status = self._redeem_then_crash_at("after_commit")
        self._assert_killed(status)

        results: list = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def worker() -> None:
            owner = self._owner()
            barrier.wait()
            try:
                r = owner.redeem_and_apply(self.request)
                with lock:
                    results.append(r.receipt["receipt_id"])
            except AuthorizationError:
                with lock:
                    results.append("refused")
            finally:
                owner.close()

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        receipt_ids = {r for r in results if r != "refused"}
        self.assertEqual(len(receipt_ids), 1, results)
        self.assertEqual(self._current_value(), "debug")
        self._assert_single_redemption()

    def _assert_single_redemption(self) -> None:
        conn = sqlite3.connect(self.resource_db, timeout=30)
        try:
            n = conn.execute(
                "SELECT COUNT(*) FROM redemptions WHERE grant_id = ?",
                (self.grant.grant["grant_id"],),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(n, 1)

    # -- scenario 4: observation unavailable -> UNKNOWN -> reconcile --------

    def test_observation_unavailable_is_unknown_then_reconciles(self) -> None:
        # Commit the effect for real.
        owner = self._owner()
        owner.redeem_and_apply(self.request)
        owner.close()

        resolver = OutcomeResolver()
        from vgi.contracts import ExecutionOutcome

        # Observation currently unavailable -> UNKNOWN (never a false COMMITTED).
        def unavailable():
            raise ConfirmationUnavailable("observer offline")

        self.assertEqual(
            resolver.resolve_with_confirmer(local_committed=True, confirmer=unavailable),
            ExecutionOutcome.UNKNOWN,
        )

        # Later, reconcile from durable evidence: the committed value is readable.
        def now_available():
            return self._current_value() == "debug"

        self.assertEqual(
            resolver.resolve_with_confirmer(local_committed=True, confirmer=now_available),
            ExecutionOutcome.COMMITTED,
        )


if __name__ == "__main__":
    unittest.main()
