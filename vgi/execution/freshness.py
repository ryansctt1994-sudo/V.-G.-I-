"""The independent freshness authority.

Its single job: decide, once and only once, whether a grant may be consumed —
and have that decision survive a rollback of the resource owner's own state.

Why it must be independent: if the record that a grant was spent lives only in
the resource database, then restoring a snapshot of that database restores the
grant's authority. The attacker replays a spent grant and it works. So the
"has this grant been spent?" record is kept here, in a separate store with its
own durability (model for a hardware monotonic counter, a TPM, or a separate
replicated service). Rolling back the resource database does not roll this back.

It also tracks a monotonic high-water mark over issued sequence numbers, as
defense in depth and as an auditable freshness signal.
"""

from __future__ import annotations

import sqlite3
from typing import Literal

ConsumeResult = Literal["ok", "replay"]


class FreshnessAuthority:
    def __init__(self, db_path: str):
        self._path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS issued (seq INTEGER PRIMARY KEY)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS consumed ("
            "  grant_id TEXT PRIMARY KEY,"
            "  seq INTEGER NOT NULL"
            ")"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL)"
        )
        self._conn.execute(
            "INSERT OR IGNORE INTO meta (k, v) VALUES ('high_water', 0)"
        )
        self._conn.execute(
            "INSERT OR IGNORE INTO meta (k, v) VALUES ('issue_counter', 0)"
        )
        self._conn.commit()

    # -- issuance (called by the grant authority) ---------------------------

    def issue_seq(self) -> int:
        """Allocate the next strictly-increasing sequence number for a grant."""
        cur = self._conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("UPDATE meta SET v = v + 1 WHERE k = 'issue_counter'")
        cur.execute("SELECT v FROM meta WHERE k = 'issue_counter'")
        seq = cur.fetchone()[0]
        cur.execute("INSERT INTO issued (seq) VALUES (?)", (seq,))
        self._conn.commit()
        return seq

    # -- consumption (called by the resource owner) -------------------------

    def consume(self, grant_id: str, seq: int) -> ConsumeResult:
        """Spend a grant exactly once. Returns 'replay' if already spent."""
        cur = self._conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        row = cur.execute(
            "SELECT 1 FROM consumed WHERE grant_id = ?", (grant_id,)
        ).fetchone()
        if row is not None:
            self._conn.rollback()
            return "replay"
        cur.execute(
            "INSERT INTO consumed (grant_id, seq) VALUES (?, ?)", (grant_id, seq)
        )
        cur.execute(
            "UPDATE meta SET v = MAX(v, ?) WHERE k = 'high_water'", (seq,)
        )
        self._conn.commit()
        return "ok"

    def is_consumed(self, grant_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM consumed WHERE grant_id = ?", (grant_id,)
        ).fetchone()
        return row is not None

    @property
    def high_water(self) -> int:
        return self._conn.execute(
            "SELECT v FROM meta WHERE k = 'high_water'"
        ).fetchone()[0]

    def close(self) -> None:
        self._conn.close()
