"""Governed replacement grants (reviewer Priority 1).

Definition of done:
  * A replacement cannot overwrite a newer update  -> enforced compare-and-set.
  * The original grant stays blocked               -> replacement never clears it.
  * The worklist records what happened to both     -> resolutions + recovery_worklist.

Plus the design note: a successful replacement resolves the operator's work item
while the original's own execution stays UNKNOWN. Both facts are preserved.

A "blocked original" is produced without fork by raising inside the crash hook at
`after_reserve`: the grant is reserved in the coordination store, the resource
transaction rolls back, and no local record is written — exactly the blocked
state a real crash at that point leaves.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest

from vgi.contracts import Grant, canonical
from vgi.crypto import KeyPair
from vgi.execution.freshness import FreshnessAuthority
from vgi.execution.resource_owner import AuthorizationError, ResourceOwner
from vgi.governance.grants import GrantAuthority, GrantError, GrantToken
from vgi.governance.policy import default_config_policy
from vgi.intelligence.proposer import Proposer


class ReplacementGovernanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp(prefix="vgi-repl-gov-")
        self.coord_db = os.path.join(self.workdir, "coord.db")
        self.resource_db = os.path.join(self.workdir, "resource.db")
        self.authority_key = KeyPair.generate()
        self.executor_key = KeyPair.generate()
        self._authority_freshness = FreshnessAuthority(self.coord_db)
        self.authority = GrantAuthority(
            self.authority_key, default_config_policy(), self._authority_freshness
        )
        self.proposer = Proposer()
        self._coord_conns: list = [self._authority_freshness]

    def tearDown(self) -> None:
        for conn in self._coord_conns:
            conn.close()

    def _owner(self, hook=None) -> ResourceOwner:
        freshness = FreshnessAuthority(self.coord_db)
        self._coord_conns.append(freshness)
        return ResourceOwner(
            self.resource_db,
            executor_key=self.executor_key,
            authority_verify_key=self.authority.verify_key,
            freshness=freshness,
            crash_hook=hook,
        )

    def _apply(self, value, *, precondition=None, supersedes=None, owner=None) -> tuple:
        proposal = self.proposer.propose_config_change(
            "log.level", value, precondition=precondition
        )
        grant = self.authority.issue(proposal, supersedes=supersedes)
        o = owner or self._owner()
        signed = o.redeem_and_apply(
            {"effect": proposal.effect, "grant_token": grant.to_dict()}
        )
        if owner is None:
            o.close()
        return signed.receipt["outcome"], grant.grant["grant_id"]

    def _blocked_original(self, value="debug") -> str:
        """Create and return the id of a genuinely blocked original grant."""
        proposal = self.proposer.propose_config_change("log.level", value)
        grant = self.authority.issue(proposal)

        def hook(boundary: str) -> None:
            if boundary == "after_reserve":
                raise RuntimeError("simulated crash after reservation")

        owner = self._owner(hook)
        with self.assertRaises(RuntimeError):
            owner.redeem_and_apply(
                {"effect": proposal.effect, "grant_token": grant.to_dict()}
            )
        owner.close()
        gid = grant.grant["grant_id"]
        # Reopen: recovery leaves a reserved-but-unrecorded grant blocked.
        owner = self._owner()
        self.assertIn(gid, owner.unresolved_grants()["blocked"])
        owner.close()
        return gid

    # -- enforcement --------------------------------------------------------

    def test_authority_refuses_replacement_without_precondition(self) -> None:
        orig = self._blocked_original()
        proposal = self.proposer.propose_config_change("log.level", "debug")  # no precond
        with self.assertRaises(GrantError):
            self.authority.issue(proposal, supersedes=orig)

    def test_owner_refuses_replacement_without_precondition(self) -> None:
        # Independent enforcement: hand-sign a replacement grant that lacks a
        # precondition (bypassing the authority) and confirm the owner refuses it.
        orig = self._blocked_original()
        proposal = self.proposer.propose_config_change("log.level", "debug")
        eid = proposal.effect_id
        grant = Grant(
            grant_id="grant-handmade",
            effect_id=eid,
            effect=dict(proposal.effect),  # precondition is None
            freshness_seq=999,
            policy_decision_id="dec-x",
            issued_at=time.time(),
            expires_at=time.time() + 300,
            supersedes=orig,
        )
        token = GrantToken(
            grant=grant.to_dict(),
            signature=self.authority_key.sign(canonical(grant.to_dict())),
            authority_key_id=self.authority_key.key_id,
        )
        owner = self._owner()
        with self.assertRaises(AuthorizationError):
            owner.redeem_and_apply({"effect": proposal.effect, "grant_token": token.to_dict()})
        owner.close()

    # -- linkage ------------------------------------------------------------

    def test_cannot_supersede_a_cleanly_committed_grant(self) -> None:
        _, clean_gid = self._apply("info")  # resolved normally, has a local record
        owner = self._owner()
        proposal = self.proposer.propose_config_change("log.level", "debug", precondition="info")
        grant = self.authority.issue(proposal, supersedes=clean_gid)
        with self.assertRaises(AuthorizationError):
            owner.redeem_and_apply({"effect": proposal.effect, "grant_token": grant.to_dict()})
        owner.close()

    def test_cannot_supersede_an_unknown_grant(self) -> None:
        owner = self._owner()
        proposal = self.proposer.propose_config_change("log.level", "debug", precondition="info")
        grant = self.authority.issue(proposal, supersedes="grant-does-not-exist")
        with self.assertRaises(AuthorizationError):
            owner.redeem_and_apply({"effect": proposal.effect, "grant_token": grant.to_dict()})
        owner.close()

    # -- scenario 3: success resolves worklist, original stays UNKNOWN -------

    def test_successful_replacement_resolves_worklist_original_stays_unknown(self) -> None:
        self._apply("info")  # establishes a reviewable prior value
        orig = self._blocked_original("debug")  # intended debug, never applied

        owner = self._owner()
        self.assertEqual(owner.current_value("log.level"), "info")  # original didn't apply
        outcome, repl = self._apply("debug", precondition="info", supersedes=orig, owner=owner)
        self.assertEqual(outcome, "applied")
        self.assertEqual(owner.current_value("log.level"), "debug")

        # Both facts preserved: the original is still blocked (its own execution
        # UNKNOWN), AND it is recorded as resolved by the replacement.
        self.assertIn(orig, owner.unresolved_grants()["blocked"])
        entry = next(e for e in owner.recovery_worklist() if e["grant_id"] == orig)
        self.assertEqual(entry["original_execution"], "UNKNOWN")
        self.assertTrue(entry["resolved"])
        self.assertEqual(entry["resolutions"], [
            {"replacement": repl, "outcome": "applied",
             "resolved_at": entry["resolutions"][0]["resolved_at"]},
        ])
        owner.close()

    # -- scenario 1: a resource update between review and redemption ---------

    def test_update_between_review_and_redemption_rejects_replacement(self) -> None:
        self._apply("info")
        orig = self._blocked_original("debug")

        owner = self._owner()
        # Operator reviews state == "info" and prepares a replacement bound to it.
        proposal = self.proposer.propose_config_change("log.level", "debug", precondition="info")
        repl_grant = self.authority.issue(proposal, supersedes=orig)

        # Before the replacement is redeemed, another authorized write moves state.
        self._apply("warn", precondition="info", owner=owner)
        self.assertEqual(owner.current_value("log.level"), "warn")

        # The replacement's compare-and-set now fails: it cannot overwrite "warn".
        signed = owner.redeem_and_apply(
            {"effect": proposal.effect, "grant_token": repl_grant.to_dict()}
        )
        self.assertEqual(signed.receipt["outcome"], "rejected")
        self.assertEqual(owner.current_value("log.level"), "warn")  # newer update survives

        # The attempt is recorded; the original is not marked resolved.
        entry = next(e for e in owner.recovery_worklist() if e["grant_id"] == orig)
        self.assertFalse(entry["resolved"])
        self.assertEqual([r["outcome"] for r in entry["resolutions"]], ["rejected"])
        owner.close()

    # -- scenario 2: concurrent replacement attempts ------------------------

    def test_concurrent_replacements_apply_at_most_once(self) -> None:
        self._apply("info")
        orig = self._blocked_original("debug")

        # Two distinct replacements, both bound to the reviewed state "info".
        grants = []
        for _ in range(2):
            p = self.proposer.propose_config_change("log.level", "debug", precondition="info")
            grants.append((p, self.authority.issue(p, supersedes=orig)))

        results: list = []
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def worker(proposal, grant) -> None:
            # Build the owner inside the thread (SQLite connections are per-thread)
            # and close both it and its coordination connection here.
            freshness = FreshnessAuthority(self.coord_db)
            owner = ResourceOwner(
                self.resource_db,
                executor_key=self.executor_key,
                authority_verify_key=self.authority.verify_key,
                freshness=freshness,
            )
            barrier.wait()
            try:
                signed = owner.redeem_and_apply(
                    {"effect": proposal.effect, "grant_token": grant.to_dict()}
                )
                with lock:
                    results.append(signed.receipt["outcome"])
            finally:
                owner.close()
                freshness.close()

        threads = [threading.Thread(target=worker, args=g) for g in grants]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(sorted(results), ["applied", "rejected"])  # exactly one applied
        owner = self._owner()
        self.assertEqual(owner.current_value("log.level"), "debug")
        entry = next(e for e in owner.recovery_worklist() if e["grant_id"] == orig)
        self.assertTrue(entry["resolved"])
        self.assertEqual(len(entry["resolutions"]), 2)  # both attempts audited
        owner.close()

    # -- crash between the replacement commit and the resolution record -----

    def test_resolution_is_reasserted_after_crash_before_record(self) -> None:
        self._apply("info")
        orig = self._blocked_original("debug")

        proposal = self.proposer.propose_config_change("log.level", "debug", precondition="info")
        repl = self.authority.issue(proposal, supersedes=orig)

        def hook(boundary: str) -> None:
            if boundary == "after_commit":
                raise RuntimeError("crash after resource commit, before resolution")

        owner = self._owner(hook)
        with self.assertRaises(RuntimeError):
            owner.redeem_and_apply({"effect": proposal.effect, "grant_token": repl.to_dict()})
        owner.close()

        # The replacement committed locally; recovery must re-assert the resolution.
        owner = self._owner()
        self.assertEqual(owner.current_value("log.level"), "debug")
        res = owner.resolutions_for(orig)
        self.assertEqual([r["replacement"] for r in res], [repl.grant["grant_id"]])
        self.assertEqual(res[0]["outcome"], "applied")
        owner.close()


if __name__ == "__main__":
    unittest.main()
