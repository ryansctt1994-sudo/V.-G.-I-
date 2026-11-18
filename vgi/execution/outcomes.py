"""Outcome resolution (EXE-06).

Turning "what happened?" into one of COMMITTED / REFUSED / UNKNOWN / CONFLICT.

The subtle case is an effect with an *external* surface — one whose real result
lives somewhere the owner cannot read back transactionally. If the local record
says the effect was issued but the external world cannot confirm it, the honest
answer is UNKNOWN, never COMMITTED. Claiming COMMITTED without confirmation is
exactly the false-success failure the evidence design exists to prevent.
"""

from __future__ import annotations

from typing import Optional

from vgi.contracts import ExecutionOutcome


class ConfirmationUnavailable(Exception):
    """Raised by a confirmer that cannot currently determine the real effect."""


class OutcomeResolver:
    def resolve(
        self, *, local_committed: bool, external_confirmation: Optional[bool]
    ) -> ExecutionOutcome:
        """
        local_committed       — did the owner durably record the effect locally?
        external_confirmation — True (confirmed), False (contradicted),
                                None (could not be determined right now).
                                For a purely local effect, pass True.
        """
        if not local_committed:
            return ExecutionOutcome.REFUSED
        if external_confirmation is None:
            return ExecutionOutcome.UNKNOWN
        if external_confirmation is True:
            return ExecutionOutcome.COMMITTED
        return ExecutionOutcome.CONFLICT

    def resolve_with_confirmer(self, *, local_committed: bool, confirmer) -> ExecutionOutcome:
        """`confirmer()` returns a bool, or raises ConfirmationUnavailable."""
        if not local_committed:
            return ExecutionOutcome.REFUSED
        try:
            confirmed = confirmer()
        except ConfirmationUnavailable:
            return ExecutionOutcome.UNKNOWN
        return self.resolve(local_committed=True, external_confirmation=confirmed)
