"""The independent coordination store: grant reservation, commitment, revocation.

This store lives OUTSIDE the resource's rollback boundary (a separate file here;
a separate service, replicated log, or hardware counter in production). Restoring
a snapshot of the resource database must not restore it.

Protocol (driven by the resource owner, inside its write lock):

    reserve(grant)        -> PENDING      written BEFORE the resource commit
    ... resource commit (effect + redemption record, atomically) ...
    mark_committed(grant) -> COMMITTED    written AFTER the resource commit

Why both writes: a write made only after the commit can be lost to a crash; a
write made only before it cannot prove the commit happened. With both, the
owner can classify every grant it is asked to redeem:

    coordination  local record   meaning                              action
    ------------  ------------   ----------------------------------   -------------------
    none          none           never attempted                      reserve, apply
    any           present        committed here                       return stored receipt
    COMMITTED     absent         resource rolled back after commit    refuse (replay)
    PENDING       absent         crashed before commit, OR committed  BLOCKED (UNKNOWN):
                                 then rolled back -- undeterminable   never auto-reexecute

The last row is the deliberate safety-over-liveness choice: when prior execution
cannot be determined, the grant is never run again automatically. Recovery is an
investigated decision and a NEW grant.

Revocation lives here too, so that the revocation check and the reservation are
one atomic transaction. The reservation is the authorization cutoff:
a revocation committed before it is honored; one committed after it is not.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Literal, Optional

PENDING = "PENDING"
COMMITTED = "COMMITTED"

ReserveResult = Literal["reserved", "revoked", "PENDING", "COMMITTED"]
RevokeResult = Literal["revoked", "too_late"]


class FreshnessAuthority:
    def __init__(self, db_path: str):
        self._path = db_path
        self._conn = sqlite3.connect(db_path, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.execute("CREATE TABLE IF NOT EXISTS issued (seq INTEGER PRIMARY KEY)")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS grants ("
            "  grant_id TEXT PRIMARY KEY,"
            "  seq INTEGER NOT NULL,"
            "  state TEXT NOT NULL,"
            "  updated_at REAL NOT NULL"
            ")"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS revoked (grant_id TEXT PRIMARY KEY, revoked_at REAL)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL)"
        )
        self._conn.execute("INSERT OR IGNORE INTO meta (k, v) VALUES ('high_water', 0)")
        self._conn.execute("INSERT OR IGNORE INTO meta (k, v) VALUES ('issue_counter', 0)")
        self._conn.commit()

    # -- issuance (called by the grant authority) ---------------------------

    def issue_seq(self) -> int:
        """Allocate the next strictly-increasing sequence number for a grant."""
        cur = self._conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            cur.execute("UPDATE meta SET v = v + 1 WHERE k = 'issue_counter'")
            seq = cur.execute("SELECT v FROM meta WHERE k = 'issue_counter'").fetchone()[0]
            cur.execute("INSERT INTO issued (seq) VALUES (?)", (seq,))
            self._conn.commit()
            return seq
        except Exception:
            self._conn.rollback()
            raise

    # -- reservation protocol (called by the resource owner) ----------------

    def reserve(self, grant_id: str, seq: int) -> ReserveResult:
        """Atomically: refuse if revoked; report existing state if any; else
        record PENDING. This transaction is the authorization cutoff."""
        cur = self._conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            if cur.execute(
                "SELECT 1 FROM revoked WHERE grant_id = ?", (grant_id,)
            ).fetchone():
                self._conn.rollback()
                return "revoked"
            row = cur.execute(
                "SELECT state FROM grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            if row is not None:
                self._conn.rollback()
                return row[0]
            cur.execute(
                "INSERT INTO grants (grant_id, seq, state, updated_at) VALUES (?, ?, ?, ?)",
                (grant_id, seq, PENDING, time.time()),
            )
            cur.execute("UPDATE meta SET v = MAX(v, ?) WHERE k = 'high_water'", (seq,))
            self._conn.commit()
            return "reserved"
        except Exception:
            self._conn.rollback()
            raise

    def mark_committed(self, grant_id: str, seq: int = 0) -> None:
        """Record that the resource commit for this grant happened. Idempotent."""
        self._conn.execute(
            "INSERT INTO grants (grant_id, seq, state, updated_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(grant_id) DO UPDATE SET state = excluded.state, "
            "updated_at = excluded.updated_at",
            (grant_id, seq, COMMITTED, time.time()),
        )
        self._conn.commit()

    def state(self, grant_id: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT state FROM grants WHERE grant_id = ?", (grant_id,)
        ).fetchone()
        return row[0] if row else None

    def grants_in_state(self, state: str) -> list:
        """Grant ids currently in `state`, oldest first."""
        return [
            r[0]
            for r in self._conn.execute(
                "SELECT grant_id FROM grants WHERE state = ? ORDER BY updated_at, grant_id",
                (state,),
            )
        ]

    def is_consumed(self, grant_id: str) -> bool:
        """True once a grant has been reserved (PENDING) or committed."""
        return self.state(grant_id) is not None

    # -- revocation (AUT-07) ------------------------------------------------

    def revoke(self, grant_id: str) -> RevokeResult:
        """Withdraw a grant's authority. Returns 'too_late' if the grant was
        already reserved, i.e. execution passed the cutoff; the revocation is
        still recorded for audit, but that execution is not stopped."""
        cur = self._conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            cur.execute(
                "INSERT OR IGNORE INTO revoked (grant_id, revoked_at) VALUES (?, ?)",
                (grant_id, time.time()),
            )
            reserved = cur.execute(
                "SELECT 1 FROM grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            self._conn.commit()
            return "too_late" if reserved else "revoked"
        except Exception:
            self._conn.rollback()
            raise

    def is_revoked(self, grant_id: str) -> bool:
        return (
            self._conn.execute(
                "SELECT 1 FROM revoked WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            is not None
        )

    @property
    def high_water(self) -> int:
        return self._conn.execute("SELECT v FROM meta WHERE k = 'high_water'").fetchone()[0]

    def close(self) -> None:
        self._conn.close()
