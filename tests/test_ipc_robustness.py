"""IPC robustness: malformed input from an ALLOWED peer must not stop the service.

Reviewer-reported defect: a JSON array crashed the handler with AttributeError,
and the serve loop did not contain it — a termination path for any allowed peer.

Runs without root: the service authorizes the test process's own uid. (This
covers the authenticated IPC handling, not OS isolation, which still needs two
uids — see test_os_isolation.)
"""

from __future__ import annotations

import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest

from vgi.crypto import KeyPair
from vgi.execution import owner_service
from vgi.execution.freshness import FreshnessAuthority
from vgi.execution.ipc import client_request
from vgi.execution.owner_service import OwnerService
from vgi.execution.resource_owner import ResourceOwner
from vgi.governance.grants import GrantAuthority
from vgi.governance.policy import default_config_policy
from vgi.intelligence.proposer import Proposer

_LEN = struct.Struct("!I")


class IPCRobustnessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = tempfile.mkdtemp(prefix="vgi-ipc-")
        self.sock = os.path.join(self.workdir, "owner.sock")
        coord_db = os.path.join(self.workdir, "coord.db")
        resource_db = os.path.join(self.workdir, "resource.db")
        self.authority = GrantAuthority(
            KeyPair.generate(), default_config_policy(), FreshnessAuthority(coord_db)
        )
        executor_key = KeyPair.generate()
        verify_key = self.authority.verify_key
        self._saved_timeout = owner_service._CONN_TIMEOUT
        owner_service._CONN_TIMEOUT = 0.5  # keep the stall test fast
        self.stop = threading.Event()

        def serve() -> None:
            # Build the owner in the thread that serves it (SQLite connections are
            # per-thread; in production the service is its own process).
            owner = ResourceOwner(
                resource_db,
                executor_key=executor_key,
                authority_verify_key=verify_key,
                freshness=FreshnessAuthority(coord_db),
            )
            OwnerService(self.sock, owner, allowed_uids={os.geteuid()}).serve_forever(
                stop_event=self.stop
            )

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        deadline = time.time() + 5
        while not os.path.exists(self.sock):
            if time.time() > deadline:
                self.fail("service socket did not appear")
            time.sleep(0.01)

    def tearDown(self) -> None:
        self.stop.set()
        self.thread.join(timeout=5)
        owner_service._CONN_TIMEOUT = self._saved_timeout

    def _raw(self, frame: bytes):
        """Send raw bytes; return the decoded response, or 'closed'."""
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.settimeout(5)
        try:
            c.connect(self.sock)
            if frame:
                c.sendall(frame)
            header = c.recv(4)
            if len(header) < 4:
                return "closed"
            (n,) = _LEN.unpack(header)
            body = b""
            while len(body) < n:
                chunk = c.recv(n - len(body))
                if not chunk:
                    return "closed"
                body += chunk
            return json.loads(body)
        except (ConnectionError, socket.timeout):
            return "closed"
        finally:
            c.close()

    @staticmethod
    def _frame(payload: bytes) -> bytes:
        return _LEN.pack(len(payload)) + payload

    def _valid_request(self) -> dict:
        proposal = Proposer().propose_config_change("log.level", "debug")
        grant = self.authority.issue(proposal)
        return {"effect": proposal.effect, "grant_token": grant.to_dict(), "request_id": "ok"}

    def test_malformed_inputs_are_refused_and_service_survives(self) -> None:
        cases = {
            "json array": self._frame(b"[1, 2, 3]"),
            "json string": self._frame(b'"hello"'),
            "json number": self._frame(b"42"),
            "invalid json": self._frame(b"{not json"),
            "invalid utf-8": self._frame(b"\xff\xfe\xfd"),
            "extra field": self._frame(json.dumps({"effect": {}, "grant_token": {}, "x": 1}).encode()),
            "grant_token is a list": self._frame(
                json.dumps({"effect": {"resource": "config", "operation": "set",
                                       "key": "k", "value": "v"},
                            "grant_token": [1]}).encode()
            ),
            "effect is a list": self._frame(json.dumps({"effect": [], "grant_token": {}}).encode()),
            "request_id not a string": self._frame(
                json.dumps({"effect": {}, "grant_token": {}, "request_id": 7}).encode()
            ),
            "oversize length header": _LEN.pack(1 << 30),
            "truncated body": _LEN.pack(100) + b"{",
        }
        for name, frame in cases.items():
            with self.subTest(case=name):
                resp = self._raw(frame)
                if resp != "closed":
                    self.assertIn(resp.get("outcome"), {"REFUSED", "UNKNOWN"}, (name, resp))
                    self.assertNotEqual(resp.get("outcome"), "COMMITTED")
                self.assertTrue(self.thread.is_alive(), f"service died on: {name}")

        # A peer that connects and stalls is timed out, not served forever.
        self.assertEqual(self._raw(b""), "closed")
        self.assertTrue(self.thread.is_alive())

        # After all of that, a valid request is still served.
        resp = client_request(self.sock, self._valid_request())
        self.assertEqual(resp["outcome"], "COMMITTED")


if __name__ == "__main__":
    unittest.main()
