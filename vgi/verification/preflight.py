"""Dependency preflight and fail-closed verification (VER-07).

The principle, stated by the spec and enforced here: *missing verification
dependencies must never produce a passing verification result.* A proof that was
never checked because its checker was absent is not a proof — it is a blocked
dependency, and it is reported as exactly that.
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    BLOCKED_DEPENDENCY = "BLOCKED_DEPENDENCY"


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    detail: str = ""
    missing: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return self.status is VerificationStatus.VERIFIED


def module_probe(module_name: str) -> Callable[[], bool]:
    """A probe that reports whether an importable module is present."""

    def probe() -> bool:
        return importlib.util.find_spec(module_name) is not None

    return probe


class DependencyPreflight:
    def __init__(self) -> None:
        self._deps: dict[str, Callable[[], bool]] = {}

    def require(self, name: str, probe: Callable[[], bool]) -> "DependencyPreflight":
        self._deps[name] = probe
        return self

    def missing(self) -> list[str]:
        out = []
        for name, probe in self._deps.items():
            try:
                present = probe()
            except Exception:
                present = False
            if not present:
                out.append(name)
        return out


class Verifier:
    """Runs a verification only if its mandatory dependencies are present.

    `claim_fn` must *actually perform* the verification and return True on
    success. Any other return value (False, None, a stub that does nothing) is
    reported as NOT_VERIFIED — a non-verifying command never counts as a pass.
    """

    def __init__(self, preflight: DependencyPreflight):
        self._preflight = preflight

    def run(self, claim_fn: Callable[[], bool], *, detail: str = "") -> VerificationResult:
        missing = self._preflight.missing()
        if missing:
            return VerificationResult(
                status=VerificationStatus.BLOCKED_DEPENDENCY,
                detail=f"missing mandatory dependencies: {', '.join(missing)}",
                missing=tuple(missing),
            )
        try:
            result = claim_fn()
        except Exception as e:  # a crashing verifier has NOT verified anything
            return VerificationResult(
                status=VerificationStatus.NOT_VERIFIED, detail=f"verifier raised: {e!r}"
            )
        if result is True:
            return VerificationResult(status=VerificationStatus.VERIFIED, detail=detail)
        return VerificationResult(
            status=VerificationStatus.NOT_VERIFIED,
            detail=detail or "verifier did not return True",
        )
