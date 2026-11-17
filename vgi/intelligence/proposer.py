"""The proposer lives in the untrusted domain.

It holds no signing keys and has no handle to the protected resource. Its only
output is a `Proposal`: a structured, non-authoritative request to change
state. In a later phase this is where a language model plans the change; the
important invariant is that swapping in a model does not grant it any authority,
because authority lives entirely in the governance and execution domains.
"""

from __future__ import annotations

import uuid
from typing import Any, Callable, Optional

from vgi.contracts import Effect, Proposal


class Proposer:
    def __init__(self, planner: Optional[Callable[[str], Effect]] = None):
        # `planner` is the pluggable reasoning step. Default is a trivial,
        # fully-deterministic stand-in so the security core is testable
        # without a model in the loop.
        self._planner = planner

    def propose_config_change(
        self, key: str, value: Any, *, precondition: Any = None, rationale: str = ""
    ) -> Proposal:
        effect = Effect(
            resource="config",
            operation="set",
            key=key,
            value=value,
            precondition=precondition,
        )
        return Proposal(
            proposal_id=f"prop-{uuid.uuid4().hex[:12]}",
            effect=effect.to_dict(),
            rationale=rationale or f"Set config[{key}] = {value!r}",
        )

    def plan(self, objective: str) -> Proposal:
        """Turn a free-form objective into a proposal via the pluggable planner."""
        if self._planner is None:
            raise RuntimeError(
                "No planner configured. Use propose_config_change() for the "
                "deterministic path, or inject a planner for model-driven plans."
            )
        effect = self._planner(objective)
        return Proposal(
            proposal_id=f"prop-{uuid.uuid4().hex[:12]}",
            effect=effect.to_dict(),
            rationale=f"Planned from objective: {objective}",
        )
