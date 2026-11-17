"""Verification preflight tests (VER-07, SEC-017, SEC-018)."""

from __future__ import annotations

import unittest

from vgi.verification import (
    DependencyPreflight,
    VerificationStatus,
    Verifier,
    module_probe,
)


class VerificationTest(unittest.TestCase):
    def test_missing_mandatory_dependency_blocks_not_passes(self) -> None:
        # SEC-018: a required checker (e.g. z3) is absent.
        preflight = DependencyPreflight().require(
            "z3", module_probe("definitely_not_installed_z3_xyz")
        )
        verifier = Verifier(preflight)
        # Even a claim_fn that would "succeed" must not pass while the dep is missing.
        result = verifier.run(lambda: True)
        self.assertEqual(result.status, VerificationStatus.BLOCKED_DEPENDENCY)
        self.assertFalse(result.passed)
        self.assertIn("z3", result.missing)

    def test_non_verifying_command_is_not_verified(self) -> None:
        # SEC-017: a "verification" that does not actually verify (returns None).
        preflight = DependencyPreflight()  # no deps required
        verifier = Verifier(preflight)

        def does_nothing():
            return None  # performed no verification

        result = verifier.run(does_nothing)
        self.assertEqual(result.status, VerificationStatus.NOT_VERIFIED)
        self.assertFalse(result.passed)

    def test_crashing_verifier_is_not_verified(self) -> None:
        verifier = Verifier(DependencyPreflight())

        def boom():
            raise RuntimeError("checker exploded")

        result = verifier.run(boom)
        self.assertEqual(result.status, VerificationStatus.NOT_VERIFIED)

    def test_present_dependency_and_real_check_verifies(self) -> None:
        # A dependency that IS present (stdlib json) and a check that returns True.
        preflight = DependencyPreflight().require("json", module_probe("json"))
        verifier = Verifier(preflight)
        result = verifier.run(lambda: 2 + 2 == 4, detail="arithmetic")
        self.assertEqual(result.status, VerificationStatus.VERIFIED)
        self.assertTrue(result.passed)


if __name__ == "__main__":
    unittest.main()
