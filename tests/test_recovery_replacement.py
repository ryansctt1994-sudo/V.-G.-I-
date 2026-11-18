"""Replacement-grant discipline after a blocked/lost attempt.

Reviewer points (recheck at 89d0ccb):

  * `set` is idempotent only absent an intervening write. Re-issuing an old
    assignment verbatim can overwrite newer state.
  * A redemption that COMMITTED is not necessarily one that APPLIED: a rejected
    precondition also commits a redemption record.

These tests encode both, using the existing compare-and-set precondition as the
safe way to issue a replacement.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from vgi.crypto import KeyPair
from vgi.execution.freshness import FreshnessAuthority
from vgi.execution.resource_owner import ResourceOwner
from vgi.governance.grants import GrantAuthority
from vgi.governance.policy import default_config_policy
from vgi.intelligence.proposer import Proposer


class ReplacementDisciplineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp(prefix="vgi-repl-")
        self.coord_db = os.path.join(self.workdir, "coord.db")
        self.authority_key = KeyPair.generate()
        self.executor_key = KeyPair.generate()
        self.authority = GrantAuthority(
            self.authority_key, default_config_policy(), FreshnessAuthority(self.coord_db)
        )
        self.proposer = Proposer()
        self.owner = ResourceOwner(
            os.path.join(self.workdir, "resource.db"),
            executor_key=self.executor_key,
            authority_verify_key=self.authority.verify_key,
            freshness=FreshnessAuthority(self.coord_db),
        )

    def _apply(self, value, precondition=None) -> str:
        proposal = self.proposer.propose_config_change(
            "log.level", value, precondition=precondition
        )
        grant = self.authority.issue(proposal)
        signed = self.owner.redeem_and_apply(
            {"effect": proposal.effect, "grant_token": grant.to_dict()}
        )
        return signed.receipt["outcome"]

    def test_verbatim_replay_of_old_assignment_overwrites_newer_state(self) -> None:
        # The hazard: an older value re-applied after a newer authorized write.
        self.assertEqual(self._apply("A"), "applied")
        self.assertEqual(self._apply("B"), "applied")  # newer authorized write
        self.assertEqual(self.owner.current_value("log.level"), "B")

        # Naive recovery: re-issue the ORIGINAL effect (set -> "A"), no precondition.
        self.assertEqual(self._apply("A"), "applied")
        self.assertEqual(self.owner.current_value("log.level"), "A")  # clobbered "B"

    def test_precondition_guarded_replacement_refuses_on_drift(self) -> None:
        # The discipline: a replacement that believed the state was still "A"
        # guards with precondition="A". Because the real state moved to "B", it is
        # rejected instead of clobbering.
        self.assertEqual(self._apply("A"), "applied")
        self.assertEqual(self._apply("B"), "applied")

        self.assertEqual(self._apply("A", precondition="A"), "rejected")
        self.assertEqual(self.owner.current_value("log.level"), "B")  # unchanged

        # A correctly-formed replacement that names the present state applies.
        self.assertEqual(self._apply("C", precondition="B"), "applied")
        self.assertEqual(self.owner.current_value("log.level"), "C")

    def test_rejected_redemption_still_commits_a_record(self) -> None:
        # COMMITTED != applied: a rejected precondition writes a committed
        # redemption record (and would show as rolled_back if later lost).
        self.assertEqual(self._apply("A"), "applied")

        proposal = self.proposer.propose_config_change(
            "log.level", "Z", precondition="WRONG"
        )
        grant = self.authority.issue(proposal)
        gid = grant.grant["grant_id"]
        signed = self.owner.redeem_and_apply(
            {"effect": proposal.effect, "grant_token": grant.to_dict()}
        )
        self.assertEqual(signed.receipt["outcome"], "rejected")

        # The grant is COMMITTED in the coordination store and has a local record,
        # even though nothing mutated. unresolved_grants() stays empty (it has a
        # local record); the outcome is only knowable from the receipt.
        self.assertEqual(
            self.owner.unresolved_grants(), {"blocked": [], "rolled_back": []}
        )
        self.assertEqual(self.owner.current_value("log.level"), "A")  # unchanged

        import sqlite3
        import json

        conn = sqlite3.connect(os.path.join(self.workdir, "resource.db"))
        row = conn.execute(
            "SELECT receipt_json FROM redemptions WHERE grant_id = ?", (gid,)
        ).fetchone()
        conn.close()
        self.assertEqual(json.loads(row[0])["receipt"]["outcome"], "rejected")


if __name__ == "__main__":
    unittest.main()
