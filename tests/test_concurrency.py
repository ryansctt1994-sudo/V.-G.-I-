"""Concurrent redemption (SEC-006): at most one authorized consumption."""

from __future__ import annotations

import os
import tempfile
import threading
import unittest

from vgi.crypto import KeyPair
from vgi.execution.freshness import FreshnessAuthority
from vgi.execution.resource_owner import AuthorizationError, ResourceOwner
from vgi.governance.grants import GrantAuthority
from vgi.governance.policy import default_config_policy
from vgi.intelligence.proposer import Proposer


class ConcurrentRedemptionTest(unittest.TestCase):
    def test_same_grant_redeemed_by_many_owners_applies_once(self) -> None:
        workdir = tempfile.mkdtemp(prefix="vgi-conc-")
        resource_db = os.path.join(workdir, "resource.db")
        freshness_db = os.path.join(workdir, "freshness.db")

        authority_key = KeyPair.generate()
        executor_key = KeyPair.generate()

        # Issue one grant, then close the issuance connection.
        issue_fresh = FreshnessAuthority(freshness_db)
        authority = GrantAuthority(authority_key, default_config_policy(), issue_fresh)
        proposal = Proposer().propose_config_change("log.level", "debug")
        grant = authority.issue(proposal)
        issue_fresh.close()
        request = {"effect": proposal.effect, "grant_token": grant.to_dict()}

        n = 10
        barrier = threading.Barrier(n)
        results: list[tuple] = []
        lock = threading.Lock()

        def worker() -> None:
            # Each worker is an independent "owner instance" on the shared stores.
            fr = FreshnessAuthority(freshness_db)
            owner = ResourceOwner(
                resource_db,
                executor_key=executor_key,
                authority_verify_key=authority.verify_key,
                freshness=fr,
            )
            barrier.wait()  # maximize contention
            try:
                r = owner.redeem_and_apply(request)
                with lock:
                    results.append(("ok", r.receipt["receipt_id"]))
            except AuthorizationError:
                with lock:
                    results.append(("refused", None))
            except Exception as e:  # pragma: no cover
                with lock:
                    results.append(("error", repr(e)))
            finally:
                owner.close()
                fr.close()

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        kinds = [r[0] for r in results]
        self.assertEqual(len(results), n)
        self.assertNotIn("error", kinds, [r for r in results if r[0] == "error"])

        # Every success refers to the SAME receipt: exactly one real application,
        # the rest were idempotent reads or refused replays.
        receipt_ids = {r[1] for r in results if r[0] == "ok"}
        self.assertEqual(len(receipt_ids), 1, f"expected one effect, got {receipt_ids}")

        # The effect landed exactly once and the value is correct.
        reader = ResourceOwner(
            resource_db,
            executor_key=executor_key,
            authority_verify_key=authority.verify_key,
            freshness=FreshnessAuthority(freshness_db),
        )
        self.assertEqual(reader.current_value("log.level"), "debug")
        reader.close()


if __name__ == "__main__":
    unittest.main()
