"""The broker coordinates one protected transaction across the three domains.

It does not hold any authority of its own. It carries a proposal to the grant
authority, carries the resulting grant to the resource owner, files the receipt
with the evidence store, and asks the witness to confirm the real effect. The
`TransactionResult` it returns is the full, inspectable evidence trail.
"""

from __future__ import annotations

from dataclasses import dataclass

from vgi.contracts import Proposal, SignedReceipt
from vgi.evidence.receipts import ReceiptStore
from vgi.evidence.witness import Reconciliation, Witness
from vgi.execution.resource_owner import ResourceOwner
from vgi.governance.grants import GrantAuthority, GrantToken


@dataclass(frozen=True)
class TransactionResult:
    proposal: Proposal
    grant: GrantToken
    receipt: SignedReceipt
    reconciliation: Reconciliation

    @property
    def outcome(self) -> str:
        return self.receipt.receipt["outcome"]

    @property
    def verified(self) -> bool:
        """True only when the effect applied AND an independent read confirms it."""
        return self.outcome in ("applied", "duplicate") and self.reconciliation.trustworthy


class Broker:
    def __init__(
        self,
        *,
        authority: GrantAuthority,
        resource_owner: ResourceOwner,
        receipts: ReceiptStore,
        witness: Witness,
    ):
        self._authority = authority
        self._owner = resource_owner
        self._receipts = receipts
        self._witness = witness

    def run(self, proposal: Proposal) -> TransactionResult:
        grant = self._authority.issue(proposal)  # GrantError if policy denies
        request = {"effect": proposal.effect, "grant_token": grant.to_dict()}
        receipt = self._owner.redeem_and_apply(request)  # AuthorizationError if denied
        self._receipts.store(receipt)
        reconciliation = self._witness.reconcile(receipt, proposal.effect)
        return TransactionResult(
            proposal=proposal,
            grant=grant,
            receipt=receipt,
            reconciliation=reconciliation,
        )
