"""Durable receipt custody, held by the assurance domain.

Receipts are stored exactly as signed by the execution domain. This store is
append-only in spirit: a receipt, once written, is never mutated. Keeping it in
a separate store (separate credentials in production) means tampering with the
resource does not let you quietly rewrite the evidence trail.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Optional

from vgi.contracts import SignedReceipt


class ReceiptStore:
    def __init__(self, db_path: str):
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS receipts ("
            "  receipt_id TEXT PRIMARY KEY,"
            "  grant_id TEXT NOT NULL,"
            "  effect_id TEXT NOT NULL,"
            "  outcome TEXT NOT NULL,"
            "  signed_json TEXT NOT NULL"
            ")"
        )
        self._conn.commit()

    def store(self, signed: SignedReceipt) -> None:
        r = signed.receipt
        self._conn.execute(
            "INSERT OR IGNORE INTO receipts "
            "(receipt_id, grant_id, effect_id, outcome, signed_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                r["receipt_id"],
                r["grant_id"],
                r["effect_id"],
                r["outcome"],
                json.dumps(signed.to_dict()),
            ),
        )
        self._conn.commit()

    def get(self, receipt_id: str) -> Optional[SignedReceipt]:
        row = self._conn.execute(
            "SELECT signed_json FROM receipts WHERE receipt_id = ?", (receipt_id,)
        ).fetchone()
        if row is None:
            return None
        return SignedReceipt(**json.loads(row[0]))

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]

    def close(self) -> None:
        self._conn.close()
