"""The protected execution domain.

Holds the real resource under its own identity and credentials. Mutates it only
in response to a valid, unconsumed, effect-bound grant. Depends on an
independent freshness authority so that a consumed grant stays consumed even if
the resource's own state is rolled back.
"""

from vgi.execution.broker import Broker, TransactionResult  # noqa: F401
from vgi.execution.freshness import FreshnessAuthority  # noqa: F401
from vgi.execution.resource_owner import (  # noqa: F401
    AuthorizationError,
    ResourceOwner,
    SignedReceipt,
)
