"""Hash-linked ledger tests (EVD-02; SEC-015) with explicit scope of what it proves."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest

from vgi.contracts import canonical
from vgi.evidence.ledger import GENESIS, HashLedger, _hash_entry


class HashLedgerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp(prefix="vgi-ledger-")
        self.path = os.path.join(self.workdir, "ledger.db")
        self.ledger = HashLedger(self.path)
        self.cps = [self.ledger.append({"event": f"e{i}", "n": i}) for i in range(5)]

    def tearDown(self) -> None:
        self.ledger.close()

    def test_clean_chain_verifies(self) -> None:
        self.assertTrue(self.ledger.verify_chain())

    def test_inplace_tamper_is_detected(self) -> None:
        # Change a record without fixing its hash.
        side = sqlite3.connect(self.path, timeout=30)
        side.execute("UPDATE ledger SET record_json = ? WHERE seq = 3", (json.dumps({"event": "forged"}),))
        side.commit()
        side.close()
        self.assertFalse(self.ledger.verify_chain())

    def test_deletion_is_detected(self) -> None:
        side = sqlite3.connect(self.path, timeout=30)
        side.execute("DELETE FROM ledger WHERE seq = 3")
        side.commit()
        side.close()
        self.assertFalse(self.ledger.verify_chain())

    def test_reorder_is_detected(self) -> None:
        # Swap the record contents of two entries (hashes now mismatch positions).
        side = sqlite3.connect(self.path, timeout=30)
        r2 = side.execute("SELECT record_json FROM ledger WHERE seq = 2").fetchone()[0]
        r4 = side.execute("SELECT record_json FROM ledger WHERE seq = 4").fetchone()[0]
        side.execute("UPDATE ledger SET record_json = ? WHERE seq = 2", (r4,))
        side.execute("UPDATE ledger SET record_json = ? WHERE seq = 4", (r2,))
        side.commit()
        side.close()
        self.assertFalse(self.ledger.verify_chain())

    def test_external_checkpoint_detects_full_rewrite_that_selfcheck_misses(self) -> None:
        # An external party anchors the current head out of band.
        external_cp = self.ledger.checkpoint()

        # Attacker with full write access rewrites the ENTIRE ledger, recomputing
        # every hash consistently (they know the algorithm).
        side = sqlite3.connect(self.path, timeout=30)
        side.execute("DELETE FROM ledger")
        prev = GENESIS
        for seq in range(1, 6):
            record = {"event": "rewritten", "n": seq}
            entry = _hash_entry(prev, seq, record)
            side.execute(
                "INSERT INTO ledger (seq, prev_hash, entry_hash, record_json) VALUES (?,?,?,?)",
                (seq, prev, entry, canonical(record).decode("utf-8")),
            )
            prev = entry
        side.commit()
        side.close()

        # LIMIT: self-verification cannot tell — the rewritten chain is internally
        # consistent.
        self.assertTrue(self.ledger.verify_chain())

        # But the external checkpoint catches it: history no longer hashes to the
        # anchored value.
        self.assertFalse(self.ledger.verify_against_checkpoint(external_cp))


if __name__ == "__main__":
    unittest.main()
