"""The authorization domain: policy evaluation and grant issuance.

This domain owns a private signing key. It can turn a permitted proposal into
a signed, single-use grant. No other domain can.
"""

from vgi.governance.grants import GrantAuthority, GrantToken  # noqa: F401
from vgi.governance.policy import PolicyDecision, PolicyService  # noqa: F401
