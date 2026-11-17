"""Input hardening (SEC-021 adjacent; supports the path-substitution claim).

The path-substitution argument is only as good as the input surface. These
tests enforce that the effect surface admits no path/descriptor field and no
malformed shape — so there is nothing for a path or symlink substitution to
attack.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from vgi.contracts import validate_effect
from vgi.execution.resource_owner import AuthorizationError
from vgi.system import build_system


class EffectValidationTest(unittest.TestCase):
    def test_validator_rejects_smuggled_path_field(self) -> None:
        with self.assertRaises(ValueError):
            validate_effect(
                {
                    "resource": "config",
                    "operation": "set",
                    "key": "log.level",
                    "value": "debug",
                    "path": "/etc/shadow",  # smuggled
                }
            )

    def test_validator_rejects_missing_fields(self) -> None:
        with self.assertRaises(ValueError):
            validate_effect({"resource": "config", "operation": "set"})

    def test_validator_rejects_non_string_key(self) -> None:
        with self.assertRaises(ValueError):
            validate_effect(
                {"resource": "config", "operation": "set", "key": 123, "value": "x"}
            )

    def test_owner_refuses_malformed_effect_even_with_valid_grant(self) -> None:
        sys = build_system(tempfile.mkdtemp(prefix="vgi-inp-"))
        try:
            proposal = sys.proposer.propose_config_change("log.level", "debug")
            grant = sys.authority.issue(proposal)
            smuggled = dict(proposal.effect)
            smuggled["path"] = "/etc/shadow"
            with self.assertRaises(AuthorizationError):
                sys.resource_owner.redeem_and_apply(
                    {"effect": smuggled, "grant_token": grant.to_dict()}
                )
            self.assertIsNone(sys.resource_owner.current_value("log.level"))
        finally:
            sys.close()


if __name__ == "__main__":
    unittest.main()
