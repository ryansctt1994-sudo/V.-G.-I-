"""VGI — a verified, governed intelligence platform.

This package is deliberately small. It implements ONE complete vertical
workflow (a protected transaction) across three independent trust domains,
rather than scaffolding many empty modules.

Trust domains (see docs/THREAT_MODEL.md):

  1. Untrusted intelligence & applications   -> vgi.intelligence
  2. Independently protected authorization    -> vgi.governance
     + protected resource execution           -> vgi.execution
  3. Independently controlled assurance        -> vgi.evidence

Everything flows over the shared, versioned contracts in vgi.contracts.
"""

__version__ = "0.1.0"
CONTRACT_VERSION = "1.0.0"
