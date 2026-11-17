"""The resource owner holds the protected resource and is its only mutator.

Trust-boundary model
--------------------
In production this process runs under its own operating-system identity, with
the resource database owned mode 0600 by that identity. No other process —
including the intelligence domain — can open the file. The *only* way to change
the resource is to present a valid grant to `redeem_and_apply`. There is no
ungated setter.

In this in-process reference implementation we model that boundary at the API
surface: `_conn` is private, and the sole public mutation entry point is
`redeem_and_apply`, which refuses to do anything without a valid, unconsumed,
effect-bound grant. The negative tests assert there is no other write path.

Redemption logic (recovery-correct)
------------------------------------
1. Verify the grant's signature, expiry, and that the requested effect is the
   exact effect the grant authorizes. A bad grant is rejected before anything
   is consumed or recorded.
2. If this grant is already in the *local* redemption ledger, return the stored
   receipt. This makes honest retries idempotent — the effect is never applied
   twice.
3. Otherwise ask the independent freshness authority to consume the grant. If
   it reports `replay`, the grant was spent before but the local ledger has no
   record of it — exactly the snapshot-rollback case — so reject.
4. Check the precondition (compare-and-set) and apply the effect together with
   the redemption record in a single resource-database transaction.
5. Sign and return a receipt. The receipt is a claim; the evidence domain
   verifies it against an independent observation.
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from typing import Any

from vgi.contracts import (
    Receipt,
    SignedReceipt,
    canonical,
    effect_identity,
    validate_effect,
)
from vgi.crypto import KeyPair, VerifyKey
from vgi.execution.freshness import FreshnessAuthority
from vgi.governance.grants import GrantToken

# SignedReceipt is defined in vgi.contracts (it crosses the execution/evidence
# boundary). Re-exported here so callers can keep importing it from execution.
__all__ = ["AuthorizationError", "ResourceOwner", "SignedReceipt"]


class AuthorizationError(Exception):
    """Raised when a request cannot be authorized. The resource is untouched."""


class ResourceOwner:
    def __init__(
        self,
        db_path: str,
        *,
        executor_key: KeyPair,
        authority_verify_key: VerifyKey,
        freshness: FreshnessAuthority,
        revocation=None,
        crash_hook=None,
    ):
        self._path = db_path
        self._key = executor_key
        self._authority = authority_verify_key
        self._freshness = freshness
        self._revocation = revocation  # optional RevocationRegistry (AUT-07)
        # crash_hook(boundary: str) -> None. A test can pass a hook that hard-kills
        # the process at a named boundary to exercise crash recovery for real.
        self._crash_hook = crash_hook
        self._conn = sqlite3.connect(db_path, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS redemptions ("
            "  grant_id TEXT PRIMARY KEY,"
            "  effect_id TEXT NOT NULL,"
            "  receipt_json TEXT NOT NULL"
            ")"
        )
        self._conn.commit()
        # Reconcile the independent freshness guard with what is durably committed
        # here, in case a crash happened after a local commit but before freshness
        # was advanced. Runs before this owner serves any request.
        self.recover()

    @property
    def executor_verify_key(self) -> VerifyKey:
        return self._key.verify_key

    def _crash(self, boundary: str) -> None:
        if self._crash_hook is not None:
            self._crash_hook(boundary)

    def recover(self) -> int:
        """Startup reconciliation: advance freshness for every locally committed
        grant it does not yet know about. Returns the number reconciled.

        This establishes the invariant the anti-rollback check relies on:
        a grant marked consumed in freshness was, at some point, committed here.
        """
        rows = self._conn.execute("SELECT grant_id FROM redemptions").fetchall()
        reconciled = 0
        for (grant_id,) in rows:
            if not self._freshness.is_consumed(grant_id):
                # seq 0: we are only recording the consumption fact, not ordering.
                self._freshness.consume(grant_id, 0)
                reconciled += 1
        return reconciled

    # -- the sole public mutation entry point -------------------------------

    def redeem_and_apply(self, request: dict) -> SignedReceipt:
        effect = request.get("effect")
        token_dict = request.get("grant_token")
        if effect is None or token_dict is None:
            raise AuthorizationError("request must carry both effect and grant_token")

        # Strict input validation: reject any malformed effect, including a
        # smuggled path/descriptor field. There is no client-controlled path.
        try:
            validate_effect(effect)
        except ValueError as e:
            raise AuthorizationError(f"invalid effect: {e}")

        token = GrantToken.from_dict(token_dict)
        grant = token.grant

        # (1) Authenticity: the grant must be signed by the expected authority.
        if token.authority_key_id != self._authority.key_id:
            raise AuthorizationError("grant signed by an unrecognized authority")
        if not self._authority.verify(canonical(grant), token.signature):
            raise AuthorizationError("grant signature is invalid")

        # (1b) Expiry.
        if time.time() > float(grant["expires_at"]):
            raise AuthorizationError("grant has expired")

        # (1c) Effect binding: the requested effect must be *exactly* the one the
        # grant authorizes. No "close enough".
        requested_id = effect_identity(effect)
        if requested_id != grant["effect_id"]:
            raise AuthorizationError("requested effect does not match grant")
        if effect_identity(grant["effect"]) != grant["effect_id"]:
            raise AuthorizationError("grant is internally inconsistent")

        grant_id = grant["grant_id"]

        # (2) Idempotent retry: already in the local ledger -> return stored receipt.
        existing = self._conn.execute(
            "SELECT receipt_json FROM redemptions WHERE grant_id = ?", (grant_id,)
        ).fetchone()
        if existing is not None:
            import json

            stored = json.loads(existing[0])
            return SignedReceipt(**stored)

        # (2b) Revocation (AUT-07). Checked only on a not-yet-consumed grant, so a
        # committed effect is never retroactively undone by a later revocation.
        if self._revocation is not None and self._revocation.is_revoked(grant_id):
            raise AuthorizationError("grant has been revoked")

        # (3) Anti-rollback (SEC-007). freshness is advanced only AFTER a local
        # commit (and reconciled on startup), so "consumed in freshness but absent
        # from the local ledger" can only mean the local ledger was rolled back
        # under us. Refuse.
        if self._freshness.is_consumed(grant_id):
            raise AuthorizationError(
                "grant consumed per freshness authority but absent locally; "
                "refusing replay across rollback"
            )

        # Crash boundary: nothing has been written yet. A crash here leaves no
        # effect and no committed receipt (scenario 1).
        self._crash("before_transaction")

        # (4) Apply the effect and record the receipt atomically. The local
        # redemption record is the exactly-once authority and the source for
        # idempotent retries.
        signed = self._apply_locked(effect, grant_id)

        # Crash boundary: the effect + receipt are durably committed, but freshness
        # has not been advanced yet. A crash here is repaired by recover() on the
        # next start; a same-process retry returns the stored receipt (scenario 3).
        self._crash("after_commit")

        # (5) Advance the independent anti-rollback guard.
        self._freshness.consume(grant_id, int(grant["freshness_seq"]))
        return signed

    # -- internals ----------------------------------------------------------

    def _apply_locked(self, effect: dict, grant_id: str) -> SignedReceipt:
        import json

        key = effect["key"]
        new_value = effect["value"]
        precondition = effect.get("precondition")
        eid = effect_identity(effect)

        cur = self._conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            # Concurrency-safe recheck inside the write lock: if a racing redeemer
            # already recorded this grant, return its receipt and apply nothing.
            dup = cur.execute(
                "SELECT receipt_json FROM redemptions WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            if dup is not None:
                self._conn.commit()
                return SignedReceipt(**json.loads(dup[0]))

            prior_row = cur.execute(
                "SELECT value FROM config WHERE key = ?", (key,)
            ).fetchone()
            prior_value = prior_row[0] if prior_row else None

            if precondition is not None and prior_value != precondition:
                receipt = Receipt(
                    receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                    grant_id=grant_id,
                    effect_id=eid,
                    outcome="rejected",
                    prior_value=prior_value,
                    new_value=prior_value,
                    applied_at=time.time(),
                )
                signed = self._sign_receipt(receipt)
                cur.execute(
                    "INSERT INTO redemptions (grant_id, effect_id, receipt_json) "
                    "VALUES (?, ?, ?)",
                    (grant_id, eid, json.dumps(signed.to_dict())),
                )
                self._conn.commit()
                return signed

            # The effect and its redemption record commit together, or not at all.
            # If the redemption ("chronicle") write fails, the effect rolls back:
            # no protected state changes without an accounted record (SEC-013).
            cur.execute(
                "INSERT INTO config (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, new_value),
            )

            # Crash boundary: the effect is written but the surrounding
            # transaction is NOT yet committed. A hard kill here must leave no
            # partial effect (scenario 2) — SQLite discards the uncommitted WAL.
            self._crash("mid_transaction")

            receipt = Receipt(
                receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                grant_id=grant_id,
                effect_id=eid,
                outcome="applied",
                prior_value=prior_value,
                new_value=new_value,
                applied_at=time.time(),
            )
            signed = self._sign_receipt(receipt)
            cur.execute(
                "INSERT INTO redemptions (grant_id, effect_id, receipt_json) "
                "VALUES (?, ?, ?)",
                (grant_id, eid, json.dumps(signed.to_dict())),
            )
            self._conn.commit()
            return signed
        except Exception:
            self._conn.rollback()
            raise

    def _sign_receipt(self, receipt: Receipt) -> SignedReceipt:
        payload = receipt.to_dict()
        signature = self._key.sign(canonical(payload))
        return SignedReceipt(
            receipt=payload,
            signature=signature,
            executor_key_id=self._key.key_id,
        )

    # -- read path used by the owner itself (NOT the independent witness) ----

    def current_value(self, key: str) -> Any:
        row = self._conn.execute(
            "SELECT value FROM config WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else None

    def close(self) -> None:
        self._conn.close()
