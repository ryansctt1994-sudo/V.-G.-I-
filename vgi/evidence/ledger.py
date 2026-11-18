"""Hash-linked evidence ledger (EVD-02) — and an honest account of its limits.

Each entry commits to the one before it:

    entry_hash = sha256( prev_hash || seq || canonical(record) )

So any change to a past record, any deletion, and any reordering breaks the
chain and is caught by `verify_chain`.

What this does NOT do — stated plainly, because the earlier summary overreached:

* **It does not establish observation independence.** Hash chaining proves the
  *integrity of a sequence relative to a known-good anchor*. It says nothing
  about whether the recorded facts are true. Independent observation is a
  *separate* trust boundary — the witness reading real state through its own
  credentials (`vgi.evidence.witness`) — not a property of this ledger.

* **Self-verification cannot catch a full rewrite.** An attacker who can rewrite
  the entire table can recompute every hash and produce a chain that
  `verify_chain` accepts. The defense is an **external checkpoint**: an
  independent party records `(seq, head_hash)` out of band; later
  `verify_against_checkpoint` detects any change to history at or before that
  anchor. The guarantee is therefore *conditional on an external anchor*, and
  `test_ledger` demonstrates both the detection and the undetected-rewrite limit.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass

from vgi.contracts import canonical

GENESIS = "0" * 64


def _hash_entry(prev_hash: str, seq: int, record: dict) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(str(seq).encode("ascii"))
    h.update(canonical(record))
    return h.hexdigest()


@dataclass(frozen=True)
class Checkpoint:
    seq: int
    head_hash: str


class HashLedger:
    def __init__(self, db_path: str):
        self._conn = sqlite3.connect(db_path, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS ledger ("
            "  seq INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  prev_hash TEXT NOT NULL,"
            "  entry_hash TEXT NOT NULL,"
            "  record_json TEXT NOT NULL"
            ")"
        )
        self._conn.commit()

    def append(self, record: dict) -> Checkpoint:
        cur = self._conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            row = cur.execute(
                "SELECT seq, entry_hash FROM ledger ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_hash = row[1] if row else GENESIS
            next_seq = (row[0] + 1) if row else 1
            entry_hash = _hash_entry(prev_hash, next_seq, record)
            cur.execute(
                "INSERT INTO ledger (seq, prev_hash, entry_hash, record_json) "
                "VALUES (?, ?, ?, ?)",
                (next_seq, prev_hash, entry_hash, canonical(record).decode("utf-8")),
            )
            self._conn.commit()
            return Checkpoint(seq=next_seq, head_hash=entry_hash)
        except Exception:
            self._conn.rollback()
            raise

    def head(self) -> Checkpoint:
        row = self._conn.execute(
            "SELECT seq, entry_hash FROM ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return Checkpoint(seq=0, head_hash=GENESIS)
        return Checkpoint(seq=row[0], head_hash=row[1])

    def checkpoint(self) -> Checkpoint:
        """The value an external anchor should store to pin current history."""
        return self.head()

    def verify_chain(self) -> bool:
        """Recompute the whole chain from genesis. Catches in-place tampering,
        deletion, and reordering — but not a fully recomputed rewrite."""
        prev_hash = GENESIS
        import json

        for seq, stored_prev, stored_entry, record_json in self._conn.execute(
            "SELECT seq, prev_hash, entry_hash, record_json FROM ledger ORDER BY seq ASC"
        ):
            if stored_prev != prev_hash:
                return False
            record = json.loads(record_json)
            if _hash_entry(prev_hash, seq, record) != stored_entry:
                return False
            prev_hash = stored_entry
        return True

    def verify_against_checkpoint(self, checkpoint: Checkpoint) -> bool:
        """Confirm history up to an externally-anchored seq still hashes to the
        externally-held value. This is what detects a full rewrite."""
        if not self.verify_chain():
            return False
        row = self._conn.execute(
            "SELECT entry_hash FROM ledger WHERE seq = ?", (checkpoint.seq,)
        ).fetchone()
        if row is None:
            return False
        return row[0] == checkpoint.head_hash

    def close(self) -> None:
        self._conn.close()
