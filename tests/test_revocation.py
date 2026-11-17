"""Revocation tests (AUT-07, SEC-008) with the declared ordering contract."""

from __future__ import annotations

import os
import tempfile
import unittest

from vgi.crypto import KeyPair
from vgi.execution.freshness import FreshnessAuthority
from vgi.execution.resource_owner import AuthorizationError, ResourceOwner
from vgi.governance.grants import GrantAuthority
from vgi.governance.policy import default_config_policy
from vgi.governance.revocation import RevocationRegistry
from vgi.intelligence.proposer import Proposer


class RevocationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp(prefix="vgi-rev-")
        authority_key = KeyPair.generate()
        executor_key = KeyPair.generate()
        self.freshness = FreshnessAuthority(os.path.join(self.workdir, "freshness.db"))
        self.authority = GrantAuthority(authority_key, default_config_policy(), self.freshness)
        self.revocation = RevocationRegistry(os.path.join(self.workdir, "revocation.db"))
        self.owner = ResourceOwner(
            os.path.join(self.workdir, "resource.db"),
            executor_key=executor_key,
            authority_verify_key=self.authority.verify_key,
            freshness=self.freshness,
            revocation=self.revocation,
        )
        self.proposer = Proposer()

    def test_revoke_before_redeem_is_refused(self) -> None:
        proposal = self.proposer.propose_config_change("log.level", "debug")
        grant = self.authority.issue(proposal)
        self.revocation.revoke(grant.grant["grant_id"])
        with self.assertRaises(AuthorizationError):
            self.owner.redeem_and_apply(
                {"effect": proposal.effect, "grant_token": grant.to_dict()}
            )
        self.assertIsNone(self.owner.current_value("log.level"))

    def test_revoke_after_commit_does_not_undo(self) -> None:
        proposal = self.proposer.propose_config_change("log.level", "info")
        grant = self.authority.issue(proposal)
        request = {"effect": proposal.effect, "grant_token": grant.to_dict()}
        applied = self.owner.redeem_and_apply(request)
        self.assertEqual(applied.receipt["outcome"], "applied")

        # Revoking after the effect committed does not reverse history; a retry
        # still returns the original receipt.
        self.revocation.revoke(grant.grant["grant_id"])
        retry = self.owner.redeem_and_apply(request)
        self.assertEqual(retry.receipt["receipt_id"], applied.receipt["receipt_id"])
        self.assertEqual(self.owner.current_value("log.level"), "info")


if __name__ == "__main__":
    unittest.main()
