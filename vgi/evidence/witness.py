"""The independent witness.

The witness answers one question honestly: *what does the protected resource
actually say right now?* It answers it by reading the resource's own store
through its own, separately-controlled read path — not by asking the resource
owner and not by trusting a receipt.

This is the concrete form of the rule "a signed receipt cannot substitute for
observing the actual protected effect." A receipt is a claim about the past;
the witness produces an observation of the present. `reconcile` puts the two
side by side, and disagreement is a finding, not a rounding error.

In production the witness has read-only credentials to a replica or to the
resource store, independent of the execution domain. Here it opens the same
SQLite file in read-only mode, which still gives it a path that does not pass
through the resource owner's API.
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any

from vgi.contracts import Observation, SignedReceipt, canonical, effect_identity
from vgi.crypto import VerifyKey

_UNSET = object()


@dataclass(frozen=True)
class Reconciliation:
    observation: Observation
    receipt_signature_valid: bool
    receipt_matches_reality: bool

    @property
    def trustworthy(self) -> bool:
        return self.receipt_signature_valid and self.receipt_matches_reality


class Witness:
    def __init__(self, resource_db_path: str, *, executor_verify_key: VerifyKey):
        # Read-only, independent connection to the real resource store.
        self._uri = f"file:{resource_db_path}?mode=ro"
        self._executor_key = executor_verify_key

    def _read(self, key: str) -> Any:
        conn = sqlite3.connect(self._uri, uri=True)
        try:
            row = conn.execute(
                "SELECT value FROM config WHERE key = ?", (key,)
            ).fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def observe(self, effect: dict, expected_value: Any = _UNSET) -> Observation:
        key = effect["key"]
        expected = effect["value"] if expected_value is _UNSET else expected_value
        witnessed = self._read(key)
        return Observation(
            observation_id=f"obs-{uuid.uuid4().hex[:12]}",
            effect_id=effect_identity(effect),
            expected_value=expected,
            witnessed_value=witnessed,
            matches=(witnessed == expected),
            observed_at=time.time(),
        )

    def reconcile(self, signed: SignedReceipt, effect: dict) -> Reconciliation:
        """Check a receipt's authenticity AND whether reality agrees with it."""
        r = signed.receipt
        sig_valid = (
            signed.executor_key_id == self._executor_key.key_id
            and self._executor_key.verify(canonical(r), signed.signature)
        )
        witnessed = self._read(effect["key"])
        # The receipt claims the resource now holds `new_value`.
        claimed = r.get("new_value")
        matches_reality = witnessed == claimed
        observation = Observation(
            observation_id=f"obs-{uuid.uuid4().hex[:12]}",
            effect_id=r.get("effect_id"),
            expected_value=claimed,
            witnessed_value=witnessed,
            matches=matches_reality,
            observed_at=time.time(),
        )
        return Reconciliation(
            observation=observation,
            receipt_signature_valid=sig_valid,
            receipt_matches_reality=matches_reality,
        )
