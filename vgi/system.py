"""One place that wires the whole platform together.

Reading this function top to bottom is the fastest way to understand the system:
who holds which key, which store is independent of which, and how a proposal
becomes a verified effect.

Note the key distribution — it *is* the security model:

* The grant authority holds the only private signing key for grants.
* The resource owner and witness hold only the authority's *public* key.
* The resource owner holds its own private key, used only to sign receipts.
* The witness holds only the resource owner's *public* key.
* The freshness authority and the resource database are separate stores.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from vgi.crypto import KeyPair
from vgi.evidence.receipts import ReceiptStore
from vgi.evidence.witness import Witness
from vgi.execution.broker import Broker
from vgi.execution.freshness import FreshnessAuthority
from vgi.execution.resource_owner import ResourceOwner
from vgi.governance.grants import GrantAuthority
from vgi.governance.policy import PolicyService, default_config_policy
from vgi.intelligence.proposer import Proposer


@dataclass
class System:
    workdir: str
    proposer: Proposer
    policy: PolicyService
    authority: GrantAuthority
    freshness: FreshnessAuthority
    resource_owner: ResourceOwner
    receipts: ReceiptStore
    witness: Witness
    broker: Broker

    # Paths exposed for tests that simulate rollback / tampering.
    resource_db: str
    freshness_db: str
    receipts_db: str

    def close(self) -> None:
        self.resource_owner.close()
        self.freshness.close()
        self.receipts.close()


def build_system(workdir: str, *, policy: PolicyService | None = None) -> System:
    os.makedirs(workdir, exist_ok=True)
    resource_db = os.path.join(workdir, "resource.db")
    freshness_db = os.path.join(workdir, "freshness.db")
    receipts_db = os.path.join(workdir, "receipts.db")

    # --- keys: each domain generates its own; private keys never leave home ---
    authority_key = KeyPair.generate()  # governance domain
    executor_key = KeyPair.generate()  # execution domain

    # --- assurance domain: independent freshness source -----------------------
    freshness = FreshnessAuthority(freshness_db)

    # --- governance domain ----------------------------------------------------
    policy = policy or default_config_policy()
    authority = GrantAuthority(authority_key, policy, freshness)

    # --- execution domain -----------------------------------------------------
    resource_owner = ResourceOwner(
        resource_db,
        executor_key=executor_key,
        authority_verify_key=authority.verify_key,  # public key only
        freshness=freshness,
    )

    # --- assurance domain: receipts + independent witness ---------------------
    receipts = ReceiptStore(receipts_db)
    witness = Witness(
        resource_db,
        executor_verify_key=resource_owner.executor_verify_key,  # public key only
    )

    # --- untrusted intelligence domain ----------------------------------------
    proposer = Proposer()

    broker = Broker(
        authority=authority,
        resource_owner=resource_owner,
        receipts=receipts,
        witness=witness,
    )

    return System(
        workdir=workdir,
        proposer=proposer,
        policy=policy,
        authority=authority,
        freshness=freshness,
        resource_owner=resource_owner,
        receipts=receipts,
        witness=witness,
        broker=broker,
        resource_db=resource_db,
        freshness_db=freshness_db,
        receipts_db=receipts_db,
    )
