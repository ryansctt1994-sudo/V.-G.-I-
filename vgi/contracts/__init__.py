"""Shared, versioned contracts exchanged between trust domains."""

from vgi.contracts.schema import (  # noqa: F401
    CONTRACT_VERSION,
    Effect,
    ExecutionOutcome,
    Grant,
    Observation,
    Proposal,
    Receipt,
    SignedReceipt,
    canonical,
    effect_identity,
    validate_effect,
)
