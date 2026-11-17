"""Revocation registry (AUT-07).

Tracks grants whose authority has been withdrawn. Kept in its own store so that
revocation is durable and independent of both the authorization issuer and the
resource owner.

Declared ordering contract (what the tests hold the system to):

* A grant revoked **before** the owner consumes it is refused.
* A grant already consumed (its effect committed) is **not** retroactively
  undone by a later revocation; a retry of that grant still returns its original
  receipt. Revocation withdraws *future* authority, it does not reverse history.
"""

from __future__ import annotations

import sqlite3
import time


class RevocationRegistry:
    def __init__(self, db_path: str):
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS revoked (grant_id TEXT PRIMARY KEY, revoked_at REAL)"
        )
        self._conn.commit()

    def revoke(self, grant_id: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO revoked (grant_id, revoked_at) VALUES (?, ?)",
            (grant_id, time.time()),
        )
        self._conn.commit()

    def is_revoked(self, grant_id: str) -> bool:
        return (
            self._conn.execute(
                "SELECT 1 FROM revoked WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            is not None
        )

    def close(self) -> None:
        self._conn.close()
