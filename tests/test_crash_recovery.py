"""Crash recovery and lost acknowledgments (DoD #6; SEC-014/024).

These use real process termination (SIGKILL, uncatchable) at explicit
transaction boundaries, then restart a fresh owner on the same durable stores
and check the recovery behavior. Scope note: this exercises the local
transactional resource (SQLite). An external, non-transactional effect would
need its own recovery guarantee; that is what the UNKNOWN outcome is for, and
scenario 4 below covers it.

Boundaries (set via the owner's crash_hook):
  before_transaction  -> nothing written anywhere            -> retry completes
  after_reserve       -> grant PENDING, resource untouched    -> BLOCKED (UNKNOWN)
  mid_transaction     -> PENDING, effect written, uncommitted -> no partial effect, BLOCKED
  after_commit        -> committed, not yet marked COMMITTED  -> retry returns original

A crash after the reservation but before the commit is indistinguishable, from
durable state alone, from "committed and then the resource was rolled back". So
those retries are BLOCKED with an UNKNOWN outcome instead of re-executing — the
reviewer-reported rollback-replay is exactly the case this prevents
(`test_crash_after_commit_then_snapshot_restore_does_not_replay`).
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import sqlite3
import tempfile
import threading
import unittest

from vgi.crypto import KeyPair
from vgi.execution.freshness import FreshnessAuthority
from vgi.execution.outcomes import ConfirmationUnavailable, OutcomeResolver
from vgi.execution.resource_owner import AuthorizationError, RecoveryBlocked, ResourceOwner
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

    def test_crash_mid_transaction_leaves_no_partial_effect_and_blocks(self) -> None:
        status = self._redeem_then_crash_at("mid_transaction")
        self._assert_killed(status)
        # No committed receipt and no partial effect.
        self.assertIsNone(self._stored_receipt_id())
        self.assertIsNone(self._current_value())
        # The grant was reserved, so a retry cannot tell this crash apart from a
        # commit-then-rollback. It is blocked, never silently re-executed.
        owner = self._owner()
        with self.assertRaises(RecoveryBlocked):
            owner.redeem_and_apply(self.request)
        self.assertIsNone(owner.current_value("log.level"))
        owner.close()

    def test_crash_after_reserve_blocks(self) -> None:
        status = self._redeem_then_crash_at("after_reserve")
        self._assert_killed(status)
        self.assertIsNone(self._stored_receipt_id())
        owner = self._owner()
        with self.assertRaises(RecoveryBlocked):
            owner.redeem_and_apply(self.request)
        self.assertIsNone(owner.current_value("log.level"))
        owner.close()

    # -- reviewer-reported defect: crash + snapshot restore -----------------

    def test_crash_after_commit_then_snapshot_restore_does_not_replay(self) -> None:
        # Pre-commit snapshot of the resource store (schema only, no redemption).
        self._owner().close()
        snap = os.path.join(self.workdir, "snap")
        os.makedirs(snap)
        for f in self._db_files():
            if os.path.exists(f):
                shutil.copy2(f, snap)

        # Commit, then die before the coordination store learns of the commit.
        self._assert_killed(self._redeem_then_crash_at("after_commit"))
        self.assertIsNotNone(self._stored_receipt_id())  # it really committed

        # Restore ONLY the resource store to the pre-commit snapshot. The
        # coordination store is outside the rollback boundary and is untouched.
        for f in self._db_files():
            if os.path.exists(f):
                os.remove(f)
        for name in os.listdir(snap):
            shutil.copy2(os.path.join(snap, name), self.workdir)

        # Restart and retry: the grant must NOT apply again.
        owner = self._owner()
        with self.assertRaises(RecoveryBlocked):
            owner.redeem_and_apply(self.request)
        self.assertIsNone(owner.current_value("log.level"))
        owner.close()
        self.assertIsNone(self._stored_receipt_id())  # no second receipt

    def _db_files(self) -> list:
        return [self.resource_db, self.resource_db + "-wal", self.resource_db + "-shm"]

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
