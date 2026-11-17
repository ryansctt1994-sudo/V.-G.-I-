"""Grant issuance.

A grant is the only thing that authorizes the resource owner to act. It is:

* **Scoped**: bound to exactly one effect identity.
* **Single-use**: carries a freshness sequence issued by the independent
  freshness authority; the resource owner consumes it exactly once.
* **Time-boxed**: has an expiry.
* **Signed**: with the authorization domain's private key, which no other
  domain holds.

The authority refuses to sign anything policy did not allow, and binds the
grant to the policy decision and the effect the decision named.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from vgi.contracts import Grant, Proposal, canonical, effect_identity
from vgi.crypto import KeyPair, VerifyKey
from vgi.governance.policy import PolicyDecision, PolicyService


class GrantError(Exception):
    pass


@dataclass(frozen=True)
class GrantToken:
    """A grant plus its detached signature. This is what crosses the wire."""

    grant: dict
    signature: str
    authority_key_id: str

    def to_dict(self) -> dict:
        return {
            "grant": self.grant,
            "signature": self.signature,
            "authority_key_id": self.authority_key_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "GrantToken":
        return cls(
            grant=d["grant"],
            signature=d["signature"],
            authority_key_id=d["authority_key_id"],
        )


class FreshnessAllocator:
    """Minimal interface the grant authority needs from the freshness source."""

    def issue_seq(self) -> int:  # pragma: no cover - interface
        raise NotImplementedError


class GrantAuthority:
    def __init__(
        self,
        key: KeyPair,
        policy: PolicyService,
        freshness: FreshnessAllocator,
        *,
        ttl_seconds: float = 300.0,
    ):
        self._key = key
        self._policy = policy
        self._freshness = freshness
        self._ttl = ttl_seconds

    @property
    def verify_key(self) -> VerifyKey:
        """Public key handed to the execution and evidence domains."""
        return self._key.verify_key

    def issue(self, proposal: Proposal) -> GrantToken:
        decision: PolicyDecision = self._policy.evaluate(proposal)
        if not decision.allowed:
            raise GrantError(f"policy denied: {decision.reason}")

        eid = effect_identity(proposal.effect)
        # Defensive: the decision must be about this exact effect.
        if decision.effect_id != eid:
            raise GrantError("policy decision does not match proposal effect")

        now = time.time()
        grant = Grant(
            grant_id=f"grant-{uuid.uuid4().hex}",
            effect_id=eid,
            effect=dict(proposal.effect),
            freshness_seq=self._freshness.issue_seq(),
            policy_decision_id=decision.decision_id,
            issued_at=now,
            expires_at=now + self._ttl,
        )
        signature = self._key.sign(canonical(grant.to_dict()))
        return GrantToken(
            grant=grant.to_dict(),
            signature=signature,
            authority_key_id=self._key.key_id,
        )
