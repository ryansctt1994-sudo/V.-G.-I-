"""Fail-closed behavior (SEC-012 policy unavailable, SEC-013 chronicle write fails)."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest

from vgi.crypto import KeyPair
from vgi.execution.freshness import FreshnessAuthority
from vgi.execution.resource_owner import ResourceOwner
from vgi.governance.grants import GrantAuthority, GrantError
from vgi.governance.policy import default_config_policy
from vgi.intelligence.proposer import Proposer


class _UnavailablePolicy:
    """Stands in for a policy service that has crashed / is unreachable."""

    ruleset_version = "unavailable"

    def evaluate(self, proposal):
        raise ConnectionError("policy service unavailable")


class FailClosedTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp(prefix="vgi-fc-")
        self.authority_key = KeyPair.generate()
        self.executor_key = KeyPair.generate()
        self.freshness = FreshnessAuthority(os.path.join(self.workdir, "freshness.db"))
        self.resource_db = os.path.join(self.workdir, "resource.db")
        self.owner = ResourceOwner(
            self.resource_db,
            executor_key=self.executor_key,
            authority_verify_key=self.authority_key.verify_key,
            freshness=self.freshness,
        )
        self.proposer = Proposer()

    def test_policy_unavailable_blocks_grant_issuance(self) -> None:
        # SEC-012: no grant can be minted while policy cannot decide. No grant,
        # no protected effect.
        authority = GrantAuthority(self.authority_key, _UnavailablePolicy(), self.freshness)
        proposal = self.proposer.propose_config_change("log.level", "debug")
        with self.assertRaises(Exception) as ctx:
            authority.issue(proposal)
        self.assertNotIsInstance(ctx.exception, GrantError)  # it's the raw unavailability
        self.assertIsNone(self.owner.current_value("log.level"))

    def test_chronicle_write_failure_rolls_back_effect(self) -> None:
        # SEC-013: if the redemption ("chronicle") record cannot be written, the
        # effect must not commit. Simulate by removing the redemptions table so
        # the record INSERT fails mid-transaction.
        authority = GrantAuthority(self.authority_key, default_config_policy(), self.freshness)
        proposal = self.proposer.propose_config_change("log.level", "debug")
        grant = authority.issue(proposal)

        # Break the chronicle out-of-band.
        side = sqlite3.connect(self.resource_db, timeout=30)
        side.execute("PRAGMA busy_timeout=30000")
        side.execute("DROP TABLE redemptions")
        side.commit()
        side.close()

        with self.assertRaises(sqlite3.OperationalError):
            self.owner.redeem_and_apply(
                {"effect": proposal.effect, "grant_token": grant.to_dict()}
            )

        # No unaccounted commit: a fresh connection sees the value unchanged.
        check = sqlite3.connect(self.resource_db, timeout=30)
        row = check.execute(
            "SELECT value FROM config WHERE key = ?", ("log.level",)
        ).fetchone()
        check.close()
        self.assertIsNone(row)


if __name__ == "__main__":
    unittest.main()
