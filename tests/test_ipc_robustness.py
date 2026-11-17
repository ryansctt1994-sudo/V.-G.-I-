"""IPC robustness: malformed input from an ALLOWED peer must not stop the service.

Reviewer-reported defect D4: a JSON array crashed the handler with AttributeError
and the serve loop did not contain it.

The same malformed-input cases run two ways:

* `SocketpairIPCTest` drives `OwnerService.serve_connection` over
  `socket.socketpair()`. It needs no filesystem path and no bind, so it runs in
  sandboxes that deny binding a Unix socket. It covers the handler logic:
  envelope validation, containment, stall timeout, and the peer-uid check.
* `BoundSocketIPCTest` runs the real `serve_forever` loop on a bound socket. It
  additionally shows the *loop* survives. If the environment refuses to create
  or bind the socket it is SKIPPED with an explicit reason (a skip verifies
  nothing, and is reported as one).

Neither needs root. Neither covers OS isolation, which needs two uids — see
test_os_isolation.
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


def _frame(payload: bytes) -> bytes:
    return _LEN.pack(len(payload)) + payload


def _read_response(sock: socket.socket):
    """Read one framed JSON response, or return 'closed' if none arrives."""
    sock.settimeout(5)
    try:
        header = sock.recv(4)
        if len(header) < 4:
            return "closed"
        (n,) = _LEN.unpack(header)
        body = b""
        while len(body) < n:
            chunk = sock.recv(n - len(body))
            if not chunk:
                return "closed"
            body += chunk
        return json.loads(body)
    except (ConnectionError, socket.timeout):
        return "closed"


def _malformed_cases() -> dict:
    ok_effect = {"resource": "config", "operation": "set", "key": "k", "value": "v"}
    return {
        "json array": _frame(b"[1, 2, 3]"),
        "json string": _frame(b'"hello"'),
        "json number": _frame(b"42"),
        "invalid json": _frame(b"{not json"),
        "invalid utf-8": _frame(b"\xff\xfe\xfd"),
        "extra field": _frame(json.dumps({"effect": {}, "grant_token": {}, "x": 1}).encode()),
        "grant_token is a list": _frame(
            json.dumps({"effect": ok_effect, "grant_token": [1]}).encode()
        ),
        "effect is a list": _frame(json.dumps({"effect": [], "grant_token": {}}).encode()),
        "request_id not a string": _frame(
            json.dumps({"effect": {}, "grant_token": {}, "request_id": 7}).encode()
        ),
        "oversize length header": _LEN.pack(1 << 30),
        "truncated body": _LEN.pack(100) + b"{",
    }


class _Fixture:
    """Builds an authority and an owner on a temp dir; subclasses add transport."""

    def _build(self) -> None:
        self.workdir = tempfile.mkdtemp(prefix="vgi-ipc-")
        self.coord_db = os.path.join(self.workdir, "coord.db")
        self.resource_db = os.path.join(self.workdir, "resource.db")
        self.authority = GrantAuthority(
            KeyPair.generate(), default_config_policy(), FreshnessAuthority(self.coord_db)
        )
        self.executor_key = KeyPair.generate()
        self._saved_timeout = owner_service._CONN_TIMEOUT
        owner_service._CONN_TIMEOUT = 0.5  # keep stall tests fast

    def _make_owner(self) -> ResourceOwner:
        return ResourceOwner(
            self.resource_db,
            executor_key=self.executor_key,
            authority_verify_key=self.authority.verify_key,
            freshness=FreshnessAuthority(self.coord_db),
        )

    def _valid_request(self) -> dict:
        proposal = Proposer().propose_config_change("log.level", "debug")
        grant = self.authority.issue(proposal)
        return {"effect": proposal.effect, "grant_token": grant.to_dict(), "request_id": "ok"}

    def _restore_timeout(self) -> None:
        owner_service._CONN_TIMEOUT = self._saved_timeout


class SocketpairIPCTest(_Fixture, unittest.TestCase):
    def setUp(self) -> None:
        try:
            a, b = socket.socketpair()
            a.close()
            b.close()
        except OSError as e:
            self.skipTest(f"BLOCKED_ENVIRONMENT: cannot create a socketpair ({e})")
        self._build()
        self.owner = self._make_owner()

    def tearDown(self) -> None:
        self.owner.close()
        self._restore_timeout()

    def _exchange(self, frame: bytes, *, allowed_uids=None):
        """Run the service on one end of a socketpair; return (response, service)."""
        service = OwnerService(
            "unused.sock",
            self.owner,
            allowed_uids={os.geteuid()} if allowed_uids is None else allowed_uids,
        )
        client, server = socket.socketpair()
        try:
            if frame:
                client.sendall(frame)
            client.shutdown(socket.SHUT_WR)  # so truncated input ends, not hangs
            service.serve_connection(server)  # must never raise
            return _read_response(client), service
        finally:
            client.close()

    def test_malformed_inputs_are_refused_and_never_raise(self) -> None:
        for name, frame in _malformed_cases().items():
            with self.subTest(case=name):
                resp, _ = self._exchange(frame)
                if resp != "closed":
                    self.assertIn(resp.get("outcome"), {"REFUSED", "UNKNOWN"}, (name, resp))
                    self.assertNotEqual(resp.get("outcome"), "COMMITTED")
        # Nothing malformed changed protected state.
        self.assertIsNone(self.owner.current_value("log.level"))

    def test_service_still_serves_after_malformed_input(self) -> None:
        for frame in _malformed_cases().values():
            self._exchange(frame)
        resp, _ = self._exchange(_frame(json.dumps(self._valid_request()).encode()))
        self.assertEqual(resp["outcome"], "COMMITTED")
        self.assertEqual(self.owner.current_value("log.level"), "debug")

    def test_stalled_peer_times_out(self) -> None:
        service = OwnerService("unused.sock", self.owner, allowed_uids={os.geteuid()})
        client, server = socket.socketpair()
        try:
            started = time.time()
            service.serve_connection(server)  # client sends nothing and stays open
            self.assertLess(time.time() - started, 5)
            self.assertEqual(_read_response(client), "closed")
        finally:
            client.close()

    def test_peer_uid_not_in_allow_list_is_refused(self) -> None:
        # Application-level allow-list only; not protection against root.
        resp, _ = self._exchange(
            _frame(json.dumps(self._valid_request()).encode()),
            allowed_uids={os.geteuid() + 12345},
        )
        self.assertEqual(resp["outcome"], "REFUSED")
        self.assertIsNone(self.owner.current_value("log.level"))


class BoundSocketIPCTest(_Fixture, unittest.TestCase):
    def setUp(self) -> None:
        self._build()
        self.sock = os.path.join(self.workdir, "owner.sock")
        try:  # probe: can this environment create and bind a Unix socket path?
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.bind(os.path.join(self.workdir, "probe.sock"))
            probe.close()
        except OSError as e:
            self._restore_timeout()
            self.skipTest(f"BLOCKED_ENVIRONMENT: cannot bind a Unix socket ({e})")

        self.stop = threading.Event()
        verify_key = self.authority.verify_key

        def serve() -> None:
            # Build the owner in the thread that serves it (SQLite connections are
            # per-thread; in production the service is its own process).
            owner = ResourceOwner(
                self.resource_db,
                executor_key=self.executor_key,
                authority_verify_key=verify_key,
                freshness=FreshnessAuthority(self.coord_db),
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
        if hasattr(self, "stop"):
            self.stop.set()
            self.thread.join(timeout=5)
        self._restore_timeout()

    def _raw(self, frame: bytes):
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            c.connect(self.sock)
            if frame:
                c.sendall(frame)
            return _read_response(c)
        finally:
            c.close()

    def test_serve_loop_survives_malformed_inputs_and_stalls(self) -> None:
        for name, frame in _malformed_cases().items():
            with self.subTest(case=name):
                resp = self._raw(frame)
                if resp != "closed":
                    self.assertIn(resp.get("outcome"), {"REFUSED", "UNKNOWN"}, (name, resp))
                self.assertTrue(self.thread.is_alive(), f"service died on: {name}")

        self.assertEqual(self._raw(b""), "closed")  # connect-and-stall is timed out
        self.assertTrue(self.thread.is_alive())

        resp = client_request(self.sock, self._valid_request())
        self.assertEqual(resp["outcome"], "COMMITTED")


if __name__ == "__main__":
    unittest.main()
