"""The verification domain.

Currently: dependency preflight and a verifier that fails closed. A missing
mandatory checker must never yield a passing verification — it yields
BLOCKED_DEPENDENCY. A command that does not actually verify yields NOT_VERIFIED,
never VERIFIED.
"""

from vgi.verification.preflight import (  # noqa: F401
    DependencyPreflight,
    VerificationResult,
    VerificationStatus,
    Verifier,
    module_probe,
)
