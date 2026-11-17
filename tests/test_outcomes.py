"""Outcome resolution tests (EXE-06, SEC-024)."""

from __future__ import annotations

import unittest

from vgi.contracts import ExecutionOutcome
from vgi.execution.outcomes import ConfirmationUnavailable, OutcomeResolver


class OutcomeResolverTest(unittest.TestCase):
    def setUp(self) -> None:
        self.r = OutcomeResolver()

    def test_local_only_effect_is_committed(self) -> None:
        self.assertEqual(
            self.r.resolve(local_committed=True, external_confirmation=True),
            ExecutionOutcome.COMMITTED,
        )

    def test_not_committed_is_refused(self) -> None:
        self.assertEqual(
            self.r.resolve(local_committed=False, external_confirmation=None),
            ExecutionOutcome.REFUSED,
        )

    def test_external_confirmation_unavailable_is_unknown_not_committed(self) -> None:
        # SEC-024: the owner recorded intent but cannot confirm the external
        # effect. The result must be UNKNOWN, never a false COMMITTED.
        outcome = self.r.resolve(local_committed=True, external_confirmation=None)
        self.assertEqual(outcome, ExecutionOutcome.UNKNOWN)
        self.assertNotEqual(outcome, ExecutionOutcome.COMMITTED)

    def test_contradicted_confirmation_is_conflict(self) -> None:
        self.assertEqual(
            self.r.resolve(local_committed=True, external_confirmation=False),
            ExecutionOutcome.CONFLICT,
        )

    def test_confirmer_that_cannot_determine_yields_unknown(self) -> None:
        def confirmer():
            raise ConfirmationUnavailable("remote endpoint unreachable")

        self.assertEqual(
            self.r.resolve_with_confirmer(local_committed=True, confirmer=confirmer),
            ExecutionOutcome.UNKNOWN,
        )


if __name__ == "__main__":
    unittest.main()
