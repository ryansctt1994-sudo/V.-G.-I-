"""The negative regression tests.

These encode the failure modes found in earlier research. A clean rebuild has
to pass all of them before it can claim to improve on anything:

  1. Direct-write denial      — no path to the resource without a valid grant.
  2. Grant integrity          — forged / tampered / mismatched grants are refused.
  3. Replay via snapshot       — a spent grant stays spent even if the resource
                                 database is rolled back (independent freshness).
  4. Receipt != observation    — a signed receipt is a claim; the witness's
                                 independent read is what decides the truth.

They also include the explicit counter-example (test 3b) showing *why* the
freshness authority must have durability independent of the resource store.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
import time
import unittest

from vgi.crypto import KeyPair
from vgi.execution.freshness import FreshnessAuthority
from vgi.execution.resource_owner import AuthorizationError, ResourceOwner
from vgi.governance.grants import GrantToken
from vgi.system import build_system


def _db_files(path: str) -> list[str]:
    return [path, path + "-wal", path + "-shm"]


def snapshot(path: str, dest_dir: str) -> None:
    os.makedirs(dest_dir, exist_ok=True)
    for f in _db_files(path):
        if os.path.exists(f):
            shutil.copy2(f, os.path.join(dest_dir, os.path.basename(f)))


def restore(path: str, src_dir: str) -> None:
    for f in _db_files(path):
        if os.path.exists(f):
            os.remove(f)
    for name in os.listdir(src_dir):
        shutil.copy2(os.path.join(src_dir, name), os.path.join(os.path.dirname(path), name))


class DirectWriteDenialTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp(prefix="vgi-neg-")
        self.sys = build_system(self.workdir)

    def tearDown(self) -> None:
        self.sys.close()

    def test_no_ungated_mutation_method_exists(self) -> None:
        owner = self.sys.resource_owner
        public = [n for n in dir(owner) if not n.startswith("_")]
        # The only mutation entry point is redeem_and_apply.
        for forbidden in ("set", "put", "write", "update", "apply", "delete"):
            self.assertNotIn(forbidden, public, f"unexpected ungated mutator: {forbidden}")

    def test_request_without_grant_is_denied(self) -> None:
        effect = self.sys.proposer.propose_config_change("log.level", "x").effect
        with self.assertRaises(AuthorizationError):
            self.sys.resource_owner.redeem_and_apply({"effect": effect})
        self.assertIsNone(self.sys.resource_owner.current_value("log.level"))

    def test_forged_grant_from_attacker_key_is_denied(self) -> None:
        # The attacker mints a grant with their OWN key, not the authority's.
        proposal = self.sys.proposer.propose_config_change("log.level", "pwned")
        attacker = KeyPair.generate()
        from vgi.contracts import Grant, canonical, effect_identity

        grant = Grant(
            grant_id="grant-forged",
            effect_id=effect_identity(proposal.effect),
            effect=dict(proposal.effect),
            freshness_seq=1,
            policy_decision_id="dec-forged",
            issued_at=time.time(),
            expires_at=time.time() + 300,
        )
        forged = GrantToken(
            grant=grant.to_dict(),
            signature=attacker.sign(canonical(grant.to_dict())),
            authority_key_id=attacker.key_id,
        )
        with self.assertRaises(AuthorizationError):
            self.sys.resource_owner.redeem_and_apply(
                {"effect": proposal.effect, "grant_token": forged.to_dict()}
            )
        self.assertIsNone(self.sys.resource_owner.current_value("log.level"))

    def test_tampered_grant_body_is_denied(self) -> None:
        # Take a legitimate grant, then change the value inside it.
        proposal = self.sys.proposer.propose_config_change("log.level", "info")
        token = self.sys.authority.issue(proposal)
        tampered = token.to_dict()
        tampered["grant"]["effect"]["value"] = "debug"  # escalate the change
        with self.assertRaises(AuthorizationError):
            self.sys.resource_owner.redeem_and_apply(
                {"effect": tampered["grant"]["effect"], "grant_token": tampered}
            )
        self.assertIsNone(self.sys.resource_owner.current_value("log.level"))

    def test_grant_for_other_effect_cannot_authorize_this_one(self) -> None:
        # A valid grant for effect A, presented alongside a different effect B.
        a = self.sys.proposer.propose_config_change("log.level", "info")
        b = self.sys.proposer.propose_config_change("log.level", "debug")
        token = self.sys.authority.issue(a)
        with self.assertRaises(AuthorizationError):
            self.sys.resource_owner.redeem_and_apply(
                {"effect": b.effect, "grant_token": token.to_dict()}
            )
        self.assertIsNone(self.sys.resource_owner.current_value("log.level"))


class ReplayAcrossSnapshotTest(unittest.TestCase):
    """The freshness authority defeats replay even after a rollback."""

    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp(prefix="vgi-fresh-")
        self.sys = build_system(self.workdir)
        self.snap_dir = os.path.join(self.workdir, "snap")

    def tearDown(self) -> None:
        self.sys.close()

    def _reopen_owner(self, freshness: FreshnessAuthority) -> ResourceOwner:
        """Open a fresh resource owner on the current files, reusing the keys.

        Models the execution process restarting after its database was restored
        from a snapshot. The caller must close the previous owner first.
        """
        owner = ResourceOwner(
            self.sys.resource_db,
            executor_key=self._executor_key,
            authority_verify_key=self._authority_vk,
            freshness=freshness,
        )
        self.sys.resource_owner = owner
        return owner

    def test_spent_grant_stays_spent_after_resource_rollback(self) -> None:
        # Capture the keys so we can reopen the owner after a rollback.
        self._executor_key = self.sys.resource_owner._key
        self._authority_vk = self.sys.authority.verify_key

        # Snapshot the resource DB BEFORE the transaction.
        snapshot(self.sys.resource_db, self.snap_dir)

        proposal = self.sys.proposer.propose_config_change("log.level", "debug")
        grant = self.sys.authority.issue(proposal)
        request = {"effect": proposal.effect, "grant_token": grant.to_dict()}
        applied = self.sys.resource_owner.redeem_and_apply(request)
        self.assertEqual(applied.receipt["outcome"], "applied")
        self.assertTrue(self.sys.freshness.is_consumed(grant.grant["grant_id"]))

        # Roll back ONLY the resource DB (the freshness store is independent).
        self.sys.resource_owner.close()
        restore(self.sys.resource_db, self.snap_dir)
        owner = self._reopen_owner(self.sys.freshness)
        # Local redemption record is gone and the value reverted...
        self.assertIsNone(owner.current_value("log.level"))

        # ...but replaying the spent grant is refused by the freshness authority.
        with self.assertRaises(AuthorizationError):
            owner.redeem_and_apply(request)
        self.assertIsNone(owner.current_value("log.level"))

    def test_counterexample_rolling_back_freshness_too_resurrects_authority(self) -> None:
        # This documents WHY freshness must be independently durable: if the
        # freshness store is rolled back together with the resource store, the
        # spent grant becomes spendable again. The architecture's guarantee is
        # exactly the independence this test removes.
        snapshot(self.sys.resource_db, self.snap_dir)
        fresh_snap = os.path.join(self.workdir, "fresh_snap")
        snapshot(self.sys.freshness_db, fresh_snap)

        proposal = self.sys.proposer.propose_config_change("log.level", "debug")
        grant = self.sys.authority.issue(proposal)
        request = {"effect": proposal.effect, "grant_token": grant.to_dict()}
        self.sys.resource_owner.redeem_and_apply(request)

        # Roll BOTH stores back to before the transaction.
        self.sys.resource_owner.close()
        self.sys.freshness.close()
        restore(self.sys.resource_db, self.snap_dir)
        restore(self.sys.freshness_db, fresh_snap)
        freshness = FreshnessAuthority(self.sys.freshness_db)
        owner = ResourceOwner(
            self.sys.resource_db,
            executor_key=self.sys.resource_owner._key,
            authority_verify_key=self.sys.authority.verify_key,
            freshness=freshness,
        )
        self.sys.resource_owner = owner
        self.sys.freshness = freshness

        # With no independent freshness, the replay succeeds. (The failure the
        # real design prevents.)
        replayed = owner.redeem_and_apply(request)
        self.assertEqual(replayed.receipt["outcome"], "applied")
        self.assertEqual(owner.current_value("log.level"), "debug")


class ReceiptIsNotObservationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp(prefix="vgi-obs-")
        self.sys = build_system(self.workdir)

    def tearDown(self) -> None:
        self.sys.close()

    def test_witness_catches_drift_between_receipt_and_reality(self) -> None:
        proposal = self.sys.proposer.propose_config_change("log.level", "debug")
        result = self.sys.broker.run(proposal)
        self.assertTrue(result.verified)  # receipt and reality agree now

        # Out-of-band corruption / drift: someone changes the real value behind
        # the resource owner's back (models rollback, bit-rot, side-channel edit).
        conn = sqlite3.connect(self.sys.resource_db)
        conn.execute("UPDATE config SET value = ? WHERE key = ?", ("info", "log.level"))
        conn.commit()
        conn.close()

        # The receipt is still perfectly valid and still says "debug".
        recon = self.sys.witness.reconcile(result.receipt, proposal.effect)
        self.assertTrue(recon.receipt_signature_valid)
        # But the independent observation disagrees with the receipt's claim.
        self.assertFalse(recon.receipt_matches_reality)
        self.assertFalse(recon.trustworthy)
        self.assertEqual(recon.observation.witnessed_value, "info")

    def test_receipt_for_a_different_effect_is_not_trustworthy(self) -> None:
        # Reviewer's reproduction: a genuine receipt for effect A, reconciled
        # against effect B whose expected value happens to match current state.
        proposal_a = self.sys.proposer.propose_config_change("log.level", "debug")
        result = self.sys.broker.run(proposal_a)
        self.assertTrue(result.verified)

        effect_b = dict(proposal_a.effect, precondition="info")  # different identity
        recon = self.sys.witness.reconcile(result.receipt, effect_b)
        self.assertTrue(recon.receipt_signature_valid)  # the receipt itself is genuine
        self.assertTrue(recon.receipt_matches_reality)  # and the value does agree
        self.assertFalse(recon.receipt_bound_to_effect)  # but it is about another effect
        self.assertFalse(recon.trustworthy)

    def test_fabricated_receipt_fails_signature_check(self) -> None:
        # An attacker fabricates a "success" receipt signed with the wrong key.
        proposal = self.sys.proposer.propose_config_change("log.level", "debug")
        from vgi.contracts import Receipt, canonical, effect_identity
        from vgi.execution.resource_owner import SignedReceipt

        attacker = KeyPair.generate()
        receipt = Receipt(
            receipt_id="rcpt-fake",
            grant_id="grant-fake",
            effect_id=effect_identity(proposal.effect),
            outcome="applied",
            prior_value=None,
            new_value="debug",
            applied_at=time.time(),
        )
        forged = SignedReceipt(
            receipt=receipt.to_dict(),
            signature=attacker.sign(canonical(receipt.to_dict())),
            executor_key_id=attacker.key_id,
        )
        recon = self.sys.witness.reconcile(forged, proposal.effect)
        self.assertFalse(recon.receipt_signature_valid)
        self.assertFalse(recon.trustworthy)


if __name__ == "__main__":
    unittest.main()
