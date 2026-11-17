"""The versioned contracts that cross trust boundaries.

Design rules that make the security properties possible:

* **Canonical encoding.** Every object that is signed or hashed is first
  serialized with `canonical()` (sorted keys, no insignificant whitespace),
  so the same logical object always produces the same bytes. Without this,
  two parties could disagree about what was signed.

* **Effect identity.** An `Effect` is the *exact* state change. Its identity
  is `sha256(canonical(effect))`. Policy approves an effect identity; the
  grant is bound to that identity; the resource owner applies only the effect
  whose identity matches the grant. There is no "approximately the approved
  change" — the identity is the contract.

* **Non-authority of proposals.** A `Proposal` carries a rationale and an
  effect, but no signature and no power. It is a request, nothing more.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional

CONTRACT_VERSION = "1.0.0"


class ExecutionOutcome(str, Enum):
    """The authoritative outcome of an attempted protected effect.

    UNKNOWN is a legitimate terminal state, not a failure to be silently turned
    into REFUSED or blindly retried: it means the system could not confirm
    whether the effect took hold, and a false COMMITTED would be worse than
    admitting uncertainty. CONFLICT means authentic signals disagree.
    """

    COMMITTED = "COMMITTED"
    REFUSED = "REFUSED"
    UNKNOWN = "UNKNOWN"
    CONFLICT = "CONFLICT"


def canonical(obj: Any) -> bytes:
    """Deterministic UTF-8 encoding used for every hash and signature."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


@dataclass(frozen=True)
class Effect:
    """The exact, authoritative description of a single state change.

    `operation` is "set". `precondition` is the value the resource is expected
    to currently hold (compare-and-set); None means "no precondition". The
    effect identity is computed over all of these fields, so changing any of
    them produces a different, separately-authorized effect.
    """

    resource: str
    operation: str
    key: str
    value: Any
    precondition: Any = None

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def identity(self) -> str:
        return effect_identity(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "Effect":
        return cls(
            resource=d["resource"],
            operation=d["operation"],
            key=d["key"],
            value=d["value"],
            precondition=d.get("precondition"),
        )


def effect_identity(effect: dict) -> str:
    """Deterministic semantic identity of an effect."""
    import hashlib

    # Only the authoritative fields participate in identity.
    core = {
        "resource": effect["resource"],
        "operation": effect["operation"],
        "key": effect["key"],
        "value": effect["value"],
        "precondition": effect.get("precondition"),
    }
    return hashlib.sha256(canonical(core)).hexdigest()


@dataclass(frozen=True)
class Proposal:
    """Produced by the (untrusted) intelligence domain. Carries no authority."""

    proposal_id: str
    effect: dict
    rationale: str
    contract_version: str = CONTRACT_VERSION

    @property
    def effect_id(self) -> str:
        return effect_identity(self.effect)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Grant:
    """A scoped, single-use authorization bound to one effect identity.

    Signed by the authorization domain. `freshness_seq` is stamped by the
    independent freshness authority and is what defeats snapshot-rollback
    replay (see vgi.execution.freshness).
    """

    grant_id: str
    effect_id: str
    effect: dict  # bound copy, so the resource owner can recompute identity
    freshness_seq: int
    policy_decision_id: str
    issued_at: float
    expires_at: float
    contract_version: str = CONTRACT_VERSION

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Grant":
        return cls(**d)


@dataclass(frozen=True)
class Receipt:
    """What the execution domain claims it did. Signed, but NOT proof on its own.

    The evidence domain treats a receipt as a *claim* to be checked against an
    independent observation of the real resource state.
    """

    receipt_id: str
    grant_id: str
    effect_id: str
    outcome: str  # "applied" | "duplicate" | "rejected"
    prior_value: Any
    new_value: Any
    applied_at: float
    contract_version: str = CONTRACT_VERSION

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Receipt":
        return cls(**d)


@dataclass(frozen=True)
class SignedReceipt:
    """A receipt plus the execution domain's detached signature over it.

    Lives in contracts because it crosses the boundary from execution to the
    evidence domain. The evidence domain verifies the signature with the
    execution domain's public key, but still treats the contents as a claim.
    """

    receipt: dict
    signature: str
    executor_key_id: str

    def to_dict(self) -> dict:
        return {
            "receipt": self.receipt,
            "signature": self.signature,
            "executor_key_id": self.executor_key_id,
        }


@dataclass(frozen=True)
class Observation:
    """An independent, direct read of the real resource by the witness."""

    observation_id: str
    effect_id: str
    expected_value: Any
    witnessed_value: Any
    matches: bool
    observed_at: float
    source: str = "witness-direct-read"

    def to_dict(self) -> dict:
        return asdict(self)
