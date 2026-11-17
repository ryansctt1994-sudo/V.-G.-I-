"""The resource owner holds the protected resource and is its only mutator.

Trust-boundary model
--------------------
In production this process runs under its own operating-system identity, with
the resource database owned mode 0600 by that identity. The *only* way to change
the resource is to present a valid grant to `redeem_and_apply`. There is no
ungated setter. (A privileged host administrator is outside the attacker model;
see docs/THREAT_MODEL.md.)

Redemption protocol
-------------------
All verification happens before anything is written. Then, holding the resource
database's write lock (BEGIN IMMEDIATE):

1. If this grant already has a local redemption record, return the stored
   receipt (idempotent retry; concurrent racers land here too).
2. Reserve the grant in the independent coordination store. That one atomic
   transaction is the authorization cutoff: it refuses a revoked grant, and it
   reports any earlier reservation:
     * COMMITTED, but no local record -> the resource was rolled back: refuse.
     * PENDING,  but no local record -> prior execution cannot be determined
       (crash before commit, or commit then rollback): RecoveryBlocked/UNKNOWN.
3. Apply the effect and write the redemption record in the same transaction;
   commit.
4. After the commit, mark the grant COMMITTED in the coordination store. A crash
   before this step is repaired by `recover()` at the next start, because the
   local record proves the commit happened.

Named boundaries (`before_transaction`, `after_reserve`, `mid_transaction`,
`after_commit`) call an optional hook so tests can kill the process — or race a
revocation — at exactly those points.
"""

from __future__ import annotations

import json
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
from vgi.execution.freshness import COMMITTED, PENDING, FreshnessAuthority
from vgi.governance.grants import GrantToken

# SignedReceipt is defined in vgi.contracts (it crosses the execution/evidence
# boundary). Re-exported here so callers can keep importing it from execution.
__all__ = ["AuthorizationError", "RecoveryBlocked", "ResourceOwner", "SignedReceipt"]


class AuthorizationError(Exception):
    """Raised when a request cannot be authorized. The resource is untouched."""


class RecoveryBlocked(AuthorizationError):
    """Prior execution of this grant cannot be determined (reserved, but no local
    record). The grant is never re-executed automatically; the outcome is UNKNOWN
    until an operator investigates and, if appropriate, issues a new grant."""


class ResourceOwner:
    def __init__(
        self,
        db_path: str,
        *,
        executor_key: KeyPair,
        authority_verify_key: VerifyKey,
        freshness: FreshnessAuthority,
        crash_hook=None,
    ):
        self._path = db_path
        self._key = executor_key
        self._authority = authority_verify_key
        self._freshness = freshness  # the independent coordination store
        # crash_hook(boundary: str) -> None, called at each named boundary.
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
        self.recover()

    @property
    def executor_verify_key(self) -> VerifyKey:
        return self._key.verify_key

    def _crash(self, boundary: str) -> None:
        if self._crash_hook is not None:
            self._crash_hook(boundary)

    def recover(self) -> int:
        """Startup reconciliation. Every grant with a local redemption record did
        commit here, so mark it COMMITTED in the coordination store (repairing a
        crash between commit and mark). Grants that are PENDING with no local
        record are deliberately left PENDING: they stay blocked."""
        rows = self._conn.execute("SELECT grant_id FROM redemptions").fetchall()
        reconciled = 0
        for (grant_id,) in rows:
            if self._freshness.state(grant_id) != COMMITTED:
                self._freshness.mark_committed(grant_id)
                reconciled += 1
        return reconciled

    def unresolved_grants(self) -> dict:
        """Grants the coordination store knows about that have no local record.

        This is the operator's worklist after a crash or a restore. Read-only.

        * ``blocked``     — reserved (PENDING), no local record. Prior execution is
          undeterminable: it may never have committed, or it may have committed and
          then been rolled back. Retries report UNKNOWN.
        * ``rolled_back`` — marked COMMITTED, no local record. The grant definitely
          committed at some point and the resource has since lost it. Retries are
          refused.

        Neither list is cleared by issuing a new grant; see THREAT_MODEL.md,
        "Recovering a blocked grant".
        """
        local = {r[0] for r in self._conn.execute("SELECT grant_id FROM redemptions")}
        return {
            "blocked": [g for g in self._freshness.grants_in_state(PENDING) if g not in local],
            "rolled_back": [
                g for g in self._freshness.grants_in_state(COMMITTED) if g not in local
            ],
        }

    # -- the sole public mutation entry point -------------------------------

    def redeem_and_apply(self, request: dict) -> SignedReceipt:
        if not isinstance(request, dict):
            raise AuthorizationError("request must be an object")
        effect = request.get("effect")
        token_dict = request.get("grant_token")
        if effect is None or token_dict is None:
            raise AuthorizationError("request must carry both effect and grant_token")

        # Strict input validation: no malformed effect, no smuggled path field.
        try:
            validate_effect(effect)
        except ValueError as e:
            raise AuthorizationError(f"invalid effect: {e}")

        try:
            token = GrantToken.from_dict(token_dict)
            grant = token.grant

            # Authenticity: signed by the expected authority.
            if token.authority_key_id != self._authority.key_id:
                raise AuthorizationError("grant signed by an unrecognized authority")
            if not self._authority.verify(canonical(grant), token.signature):
                raise AuthorizationError("grant signature is invalid")

            if time.time() > float(grant["expires_at"]):
                raise AuthorizationError("grant has expired")

            # Effect binding: exactly the authorized effect, nothing "close".
            if effect_identity(effect) != grant["effect_id"]:
                raise AuthorizationError("requested effect does not match grant")
            if effect_identity(grant["effect"]) != grant["effect_id"]:
                raise AuthorizationError("grant is internally inconsistent")

            grant_id = grant["grant_id"]
            seq = int(grant["freshness_seq"])
        except AuthorizationError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            raise AuthorizationError(f"malformed grant token: {type(e).__name__}")

        # Fast path for honest retries (re-checked under the lock below).
        existing = self._conn.execute(
            "SELECT receipt_json FROM redemptions WHERE grant_id = ?", (grant_id,)
        ).fetchone()
        if existing is not None:
            return SignedReceipt(**json.loads(existing[0]))

        self._crash("before_transaction")

        signed = self._redeem_locked(effect, grant_id, seq)

        self._crash("after_commit")
        self._freshness.mark_committed(grant_id, seq)
        return signed

    # -- internals ----------------------------------------------------------

    def _redeem_locked(self, effect: dict, grant_id: str, seq: int) -> SignedReceipt:
        key = effect["key"]
        new_value = effect["value"]
        precondition = effect.get("precondition")
        eid = effect_identity(effect)

        cur = self._conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            # (1) Already redeemed here (honest retry, or a racer won).
            dup = cur.execute(
                "SELECT receipt_json FROM redemptions WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            if dup is not None:
                self._conn.commit()
                return SignedReceipt(**json.loads(dup[0]))

            # (2) Authorization cutoff: atomic revocation check + reservation in the
            # coordination store, outside the resource's rollback boundary.
            reservation = self._freshness.reserve(grant_id, seq)
            if reservation == "revoked":
                raise AuthorizationError("grant has been revoked")
            if reservation == COMMITTED:
                raise AuthorizationError(
                    "grant committed per coordination store but absent locally; "
                    "resource state was rolled back - refusing replay"
                )
            if reservation == PENDING:
                raise RecoveryBlocked(
                    "grant was reserved but has no local record: prior execution "
                    "cannot be determined; refusing to re-execute (outcome UNKNOWN)"
                )

            self._crash("after_reserve")

            # (3) Apply + record atomically.
            prior_row = cur.execute(
                "SELECT value FROM config WHERE key = ?", (key,)
            ).fetchone()
            prior_value = prior_row[0] if prior_row else None

            if precondition is not None and prior_value != precondition:
                outcome, final_value = "rejected", prior_value
            else:
                # The effect and its redemption record commit together, or not at
                # all (SEC-013): a failed chronicle write rolls the effect back.
                cur.execute(
                    "INSERT INTO config (key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, new_value),
                )
                self._crash("mid_transaction")
                outcome, final_value = "applied", new_value

            receipt = Receipt(
                receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                grant_id=grant_id,
                effect_id=eid,
                outcome=outcome,
                prior_value=prior_value,
                new_value=final_value,
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
        return SignedReceipt(
            receipt=payload,
            signature=self._key.sign(canonical(payload)),
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
