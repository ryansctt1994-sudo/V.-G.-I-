"""Happy-path and idempotency tests for the protected transaction."""

from __future__ import annotations

import tempfile
import unittest

from vgi.system import build_system


class ProtectedTransactionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp(prefix="vgi-test-")
        self.sys = build_system(self.workdir)

    def tearDown(self) -> None:
        self.sys.close()

    def test_proposal_applies_and_is_independently_verified(self) -> None:
        proposal = self.sys.proposer.propose_config_change("log.level", "debug")
        result = self.sys.broker.run(proposal)

        self.assertEqual(result.outcome, "applied")
        self.assertTrue(result.verified)
        self.assertTrue(result.reconciliation.receipt_signature_valid)
        self.assertTrue(result.reconciliation.receipt_matches_reality)
        # The resource owner's own read agrees with the witness's independent read.
        self.assertEqual(self.sys.resource_owner.current_value("log.level"), "debug")
        self.assertEqual(result.reconciliation.observation.witnessed_value, "debug")
        self.assertEqual(self.sys.receipts.count(), 1)

    def test_retry_of_same_grant_is_idempotent(self) -> None:
        # Build a grant once, then submit it to the resource owner twice.
        proposal = self.sys.proposer.propose_config_change("max.retries", "5")
        grant = self.sys.authority.issue(proposal)
        request = {"effect": proposal.effect, "grant_token": grant.to_dict()}

        first = self.sys.resource_owner.redeem_and_apply(request)
        second = self.sys.resource_owner.redeem_and_apply(request)

        self.assertEqual(first.receipt["outcome"], "applied")
        # Second redemption returns the SAME receipt and does not re-apply.
        self.assertEqual(second.receipt["receipt_id"], first.receipt["receipt_id"])
        self.assertEqual(self.sys.resource_owner.current_value("max.retries"), "5")

    def test_precondition_mismatch_is_rejected_cleanly(self) -> None:
        # Compare-and-set with a wrong expected prior value.
        proposal = self.sys.proposer.propose_config_change(
            "feature.enabled", "true", precondition="UNEXPECTED"
        )
        result = self.sys.broker.run(proposal)
        self.assertEqual(result.outcome, "rejected")
        self.assertFalse(result.verified)
        # Nothing was written.
        self.assertIsNone(self.sys.resource_owner.current_value("feature.enabled"))

    def test_policy_denies_unlisted_key(self) -> None:
        from vgi.governance.grants import GrantError

        proposal = self.sys.proposer.propose_config_change("not.allowed", "x")
        with self.assertRaises(GrantError):
            self.sys.broker.run(proposal)


if __name__ == "__main__":
    unittest.main()
