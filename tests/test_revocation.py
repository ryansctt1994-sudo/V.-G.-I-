"""Revocation (AUT-07, SEC-008) under an explicit authorization cutoff.

Contract: the reservation in the coordination store is the cutoff, and it is
atomic with the revocation check.
  * A revocation committed before the reservation is honored -> refused.
  * A revocation committed after it does not stop that execution; `revoke`
    reports "too_late" so the caller knows.
  * A committed effect is never undone by a later revocation.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from vgi.crypto import KeyPair
from vgi.execution.freshness import FreshnessAuthority
from vgi.execution.resource_owner import AuthorizationError, ResourceOwner
from vgi.governance.grants import GrantAuthority
from vgi.governance.policy import default_config_policy
from vgi.intelligence.proposer import Proposer


class RevocationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp(prefix="vgi-rev-")
        self.resource_db = os.path.join(self.workdir, "resource.db")
        self.coord_db = os.path.join(self.workdir, "coord.db")
        self.authority_key = KeyPair.generate()
        self.executor_key = KeyPair.generate()
        self.coord = FreshnessAuthority(self.coord_db)
        self.authority = GrantAuthority(self.authority_key, default_config_policy(), self.coord)
        self.proposer = Proposer()

    def _owner(self, hook=None) -> ResourceOwner:
        return ResourceOwner(
            self.resource_db,
            executor_key=self.executor_key,
            authority_verify_key=self.authority.verify_key,
            freshness=FreshnessAuthority(self.coord_db),
            crash_hook=hook,
        )

    def _grant(self, value: str):
        proposal = self.proposer.propose_config_change("log.level", value)
        grant = self.authority.issue(proposal)
        return {"effect": proposal.effect, "grant_token": grant.to_dict()}, grant.grant["grant_id"]

    def test_revoke_before_redeem_is_refused(self) -> None:
        request, gid = self._grant("debug")
        self.assertEqual(self.coord.revoke(gid), "revoked")
        owner = self._owner()
        with self.assertRaises(AuthorizationError):
            owner.redeem_and_apply(request)
        self.assertIsNone(owner.current_value("log.level"))

    def test_revoke_racing_after_early_checks_is_still_honored(self) -> None:
        # Reviewer's reproduction: the revocation lands after the early checks but
        # before the transaction. The atomic cutoff must still refuse it.
        request, gid = self._grant("debug")

        def hook(boundary: str) -> None:
            if boundary == "before_transaction":
                self.coord.revoke(gid)

        owner = self._owner(hook)
        with self.assertRaises(AuthorizationError):
            owner.redeem_and_apply(request)
        self.assertIsNone(owner.current_value("log.level"))

    def test_revoke_after_cutoff_is_too_late_and_reported(self) -> None:
        request, gid = self._grant("debug")
        results = []

        def hook(boundary: str) -> None:
            if boundary == "after_reserve":
                results.append(self.coord.revoke(gid))

        owner = self._owner(hook)
        receipt = owner.redeem_and_apply(request)
        self.assertEqual(receipt.receipt["outcome"], "applied")
        self.assertEqual(results, ["too_late"])
        self.assertTrue(self.coord.is_revoked(gid))  # still recorded for audit

    def test_revoke_after_commit_does_not_undo(self) -> None:
        request, gid = self._grant("info")
        owner = self._owner()
        applied = owner.redeem_and_apply(request)
        self.assertEqual(self.coord.revoke(gid), "too_late")
        retry = owner.redeem_and_apply(request)
        self.assertEqual(retry.receipt["receipt_id"], applied.receipt["receipt_id"])
        self.assertEqual(owner.current_value("log.level"), "info")


if __name__ == "__main__":
    unittest.main()
