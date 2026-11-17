"""Policy: decide whether a proposed effect is permitted.

Policy is independent of the intelligence that produced the proposal. It
evaluates the *effect* against a versioned ruleset and returns a decision that
is bound to the effect identity. The grant authority will only sign a decision
that is `allowed`, and only for the exact effect the decision names.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from vgi.contracts import Proposal, effect_identity


@dataclass(frozen=True)
class PolicyDecision:
    decision_id: str
    effect_id: str
    allowed: bool
    reason: str
    ruleset_version: str


# A rule takes the effect dict and returns None if it passes, or a string
# reason if it fails.
Rule = Callable[[dict], Optional[str]]


class PolicyService:
    def __init__(self, ruleset_version: str = "policy-1.0.0"):
        self.ruleset_version = ruleset_version
        self._rules: list[Rule] = []

    def add_rule(self, rule: Rule) -> "PolicyService":
        self._rules.append(rule)
        return self

    def evaluate(self, proposal: Proposal) -> PolicyDecision:
        effect = proposal.effect
        eid = effect_identity(effect)
        for rule in self._rules:
            reason = rule(effect)
            if reason is not None:
                return PolicyDecision(
                    decision_id=f"dec-{uuid.uuid4().hex[:12]}",
                    effect_id=eid,
                    allowed=False,
                    reason=reason,
                    ruleset_version=self.ruleset_version,
                )
        return PolicyDecision(
            decision_id=f"dec-{uuid.uuid4().hex[:12]}",
            effect_id=eid,
            allowed=True,
            reason="all rules passed",
            ruleset_version=self.ruleset_version,
        )


# ---- A small default ruleset for the config resource -----------------------

def allowlist_keys(*keys: str) -> Rule:
    allowed = set(keys)

    def rule(effect: dict) -> Optional[str]:
        if effect.get("resource") != "config":
            return f"unknown resource {effect.get('resource')!r}"
        if effect.get("key") not in allowed:
            return f"key {effect.get('key')!r} is not in the policy allowlist"
        return None

    return rule


def only_operation(op: str) -> Rule:
    def rule(effect: dict) -> Optional[str]:
        if effect.get("operation") != op:
            return f"operation {effect.get('operation')!r} not permitted"
        return None

    return rule


def max_value_length(n: int) -> Rule:
    def rule(effect: dict) -> Optional[str]:
        v = effect.get("value")
        if isinstance(v, str) and len(v) > n:
            return f"value too long ({len(v)} > {n})"
        return None

    return rule


def default_config_policy() -> PolicyService:
    """A reasonable starter policy for the demo/config resource."""
    return (
        PolicyService()
        .add_rule(only_operation("set"))
        .add_rule(allowlist_keys("feature.enabled", "log.level", "max.retries"))
        .add_rule(max_value_length(256))
    )
