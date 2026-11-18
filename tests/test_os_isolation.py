"""OS-enforced isolation tests — the keystone of the execution boundary.

These run the resource owner as one operating-system user and the requester as a
*different* user, and check that the kernel — not merely the API — denies every
path to protected state except the grant-gated socket.

Covers, under the declared attacker model (a requester that does NOT already
control the owner's uid or the kernel):

  SEC-001  direct write to the protected database        -> OS denies
  SEC-002  access to the protected WAL / sibling files   -> OS denies
  SEC-003  path / symlink substitution                   -> impossible by design
  SEC-004  inherited privileged descriptor               -> none exists
  (creds)  reading the owner's key material              -> OS denies
  EXE-02   authenticated IPC                             -> only allowed uid acts
  AUT      effect binding over the wire                  -> wrong-effect refused

Requires root (to drop into two different uids) and two distinct non-root users.
Skipped cleanly otherwise.
"""

from __future__ import annotations

import json
import os
import pwd
import shutil
import socket
import tempfile
import time
import unittest

from vgi.crypto import KeyPair
from vgi.execution.freshness import FreshnessAuthority
from vgi.execution.ipc import client_request
from vgi.execution.owner_service import OwnerService, build_owner, write_keyfile
from vgi.governance.grants import GrantAuthority
from vgi.governance.policy import default_config_policy
from vgi.intelligence.proposer import Proposer


def _pick_two_nonroot_users():
    candidates = ["nobody", "ubuntu", "claude", "daemon", "bin"]
    found = []
    for name in candidates:
        try:
            pw = pwd.getpwnam(name)
        except KeyError:
            continue
        if pw.pw_uid != 0 and pw.pw_uid not in [u.pw_uid for u in found]:
            found.append(pw)
        if len(found) == 2:
            return found[0], found[1]
    return None


def _drop_privs(uid: int, gid: int) -> None:
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


ROOT = os.geteuid() == 0
USERS = _pick_two_nonroot_users()


@unittest.skipUnless(ROOT and USERS, "needs root and two non-root users")
class OSIsolationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.owner_pw, self.req_pw = USERS
        self.base = tempfile.mkdtemp(prefix="vgi-os-")
        # mkdtemp is 0700 (root-owned). Make the base traversable by others so the
        # owner uid can reach secret/ and the requester uid can reach sock/; the
        # per-subdir modes below are what actually enforce isolation.
        os.chmod(self.base, 0o755)
        self.secret_dir = os.path.join(self.base, "secret")
        self.sock_dir = os.path.join(self.base, "sock")
        os.makedirs(self.secret_dir)
        os.makedirs(self.sock_dir)

        self.resource_db = os.path.join(self.secret_dir, "resource.db")
        self.freshness_db = os.path.join(self.secret_dir, "freshness.db")
        self.sock_path = os.path.join(self.sock_dir, "owner.sock")
        self.err_log = os.path.join(self.sock_dir, "owner_error.log")

        # Keys: authority signs grants (private stays here); owner gets its own
        # executor key + the authority's public key via the keyfile.
        self.authority_key = KeyPair.generate()
        self.executor_key = KeyPair.generate()
        write_keyfile(
            self.secret_dir, executor=self.executor_key, authority_pub=self.authority_key.verify_key
        )

        # Hand the whole secret dir to the owner uid; lock everyone else out.
        for root, dirs, files in os.walk(self.secret_dir):
            os.chown(root, self.owner_pw.pw_uid, self.owner_pw.pw_gid)
            for name in files:
                os.chown(os.path.join(root, name), self.owner_pw.pw_uid, self.owner_pw.pw_gid)
        os.chmod(self.secret_dir, 0o700)
        # The socket dir is owner-owned but world-traversable so the requester can
        # reach the socket (authentication is by SO_PEERCRED, not by path).
        os.chown(self.sock_dir, self.owner_pw.pw_uid, self.owner_pw.pw_gid)
        os.chmod(self.sock_dir, 0o755)

        self.owner_pid = self._start_owner()
        self._await_socket()

    def tearDown(self) -> None:
        if getattr(self, "owner_pid", None):
            try:
                os.kill(self.owner_pid, 9)
                os.waitpid(self.owner_pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
        shutil.rmtree(self.base, ignore_errors=True)

    # -- process orchestration ---------------------------------------------

    def _start_owner(self) -> int:
        pid = os.fork()
        if pid == 0:  # child -> becomes the owner
            try:
                _drop_privs(self.owner_pw.pw_uid, self.owner_pw.pw_gid)
                owner = build_owner(
                    self.secret_dir,
                    resource_db=self.resource_db,
                    freshness_db=self.freshness_db,
                )
                service = OwnerService(
                    self.sock_path, owner, allowed_uids={self.req_pw.pw_uid}
                )
                service.serve_forever()
            except BaseException as e:  # pragma: no cover - diagnostic path
                import traceback

                try:
                    with open(self.err_log, "w") as f:
                        f.write(f"{e}\n{traceback.format_exc()}")
                except Exception:
                    pass
                os._exit(1)
            os._exit(0)
        return pid

    def _await_socket(self, timeout: float = 5.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(self.sock_path):
                return
            if os.path.exists(self.err_log):
                with open(self.err_log) as f:
                    self.fail(f"owner process failed to start:\n{f.read()}")
            time.sleep(0.02)
        self.fail("owner socket did not appear in time")

    def _issue_grant(self, key: str, value: str, *, precondition=None):
        proposer = Proposer()
        proposal = proposer.propose_config_change(key, value, precondition=precondition)
        freshness = FreshnessAuthority(os.path.join(self.base, "auth_freshness.db"))
        authority = GrantAuthority(self.authority_key, default_config_policy(), freshness)
        token = authority.issue(proposal)
        # Close the authority's issuance store so its fds are not inherited by a
        # later-forked requester (harness hygiene for the SEC-004 assertion).
        freshness.close()
        return proposal, token

    def _run_as_requester(self, fn) -> dict:
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:  # child -> becomes the requester
            os.close(r)
            try:
                _drop_privs(self.req_pw.pw_uid, self.req_pw.pw_gid)
                result = fn()
            except BaseException as e:  # pragma: no cover
                result = {"child_error": repr(e)}
            os.write(w, json.dumps(result).encode())
            os.close(w)
            os._exit(0)
        os.close(w)
        chunks = []
        while True:
            b = os.read(r, 65536)
            if not b:
                break
            chunks.append(b)
        os.close(r)
        os.waitpid(pid, 0)
        return json.loads(b"".join(chunks).decode())

    # -- the test ----------------------------------------------------------

    def test_kernel_isolation_and_authenticated_ipc(self) -> None:
        proposal, grant = self._issue_grant("log.level", "debug")
        grant_token = grant.to_dict()
        effect = proposal.effect

        resource_db = self.resource_db
        wal = self.resource_db + "-wal"
        keyfile = os.path.join(self.secret_dir, "owner_keys.json")
        sock_path = self.sock_path
        protected_prefixes = (self.resource_db, self.freshness_db)

        def requester_actions() -> dict:
            out: dict = {}

            # SEC-001: direct write to the protected DB.
            try:
                with open(resource_db, "r+b") as f:
                    f.write(b"x")
                out["sec001"] = "WROTE(BAD)"
            except OSError as e:
                out["sec001"] = f"DENIED:{type(e).__name__}"

            # SEC-002: access the WAL / sibling file (and the directory itself).
            try:
                open(wal, "rb").read()
                out["sec002_wal"] = "READ(BAD)"
            except OSError as e:
                out["sec002_wal"] = f"DENIED:{type(e).__name__}"
            try:
                os.listdir(os.path.dirname(resource_db))
                out["sec002_listdir"] = "LISTED(BAD)"
            except OSError as e:
                out["sec002_listdir"] = f"DENIED:{type(e).__name__}"

            # creds: try to steal the owner's keys.
            try:
                open(keyfile, "rb").read()
                out["creds"] = "READ(BAD)"
            except OSError as e:
                out["creds"] = f"DENIED:{type(e).__name__}"

            # SEC-004: no inherited descriptor to protected state.
            leaked = []
            fd_dir = "/proc/self/fd"
            if os.path.isdir(fd_dir):
                for fd in os.listdir(fd_dir):
                    try:
                        target = os.readlink(os.path.join(fd_dir, fd))
                    except OSError:
                        continue
                    if any(target.startswith(p) for p in protected_prefixes):
                        leaked.append(target)
            out["sec004_leaked_fds"] = leaked

            # EXE-02 happy path: the authorized uid acts through the socket.
            resp1 = client_request(
                sock_path, {"effect": effect, "grant_token": grant_token, "request_id": "r1"}
            )
            out["ipc_first"] = {
                "outcome": resp1.get("outcome"),
                "ro": resp1.get("receipt_outcome"),
                "rid": resp1.get("receipt", {}).get("receipt", {}).get("receipt_id"),
            }

            # Idempotent retry over IPC (lost-ack style): same grant again. The
            # owner returns the SAME receipt and does not re-apply.
            resp2 = client_request(
                sock_path, {"effect": effect, "grant_token": grant_token, "request_id": "r1"}
            )
            out["ipc_retry"] = {
                "outcome": resp2.get("outcome"),
                "ro": resp2.get("receipt_outcome"),
                "rid": resp2.get("receipt", {}).get("receipt", {}).get("receipt_id"),
            }

            return out

        res = self._run_as_requester(requester_actions)
        self.assertNotIn("child_error", res, res.get("child_error"))

        # Kernel denied every direct path.
        self.assertTrue(res["sec001"].startswith("DENIED"), res["sec001"])
        self.assertTrue(res["sec002_wal"].startswith("DENIED"), res["sec002_wal"])
        self.assertTrue(res["sec002_listdir"].startswith("DENIED"), res["sec002_listdir"])
        self.assertTrue(res["creds"].startswith("DENIED"), res["creds"])
        self.assertEqual(res["sec004_leaked_fds"], [])

        # Grant-gated IPC succeeded, and the retry was idempotent: same receipt,
        # no re-application.
        self.assertEqual(res["ipc_first"]["outcome"], "COMMITTED")
        self.assertEqual(res["ipc_first"]["ro"], "applied")
        self.assertEqual(res["ipc_retry"]["outcome"], "COMMITTED")
        self.assertEqual(res["ipc_retry"]["rid"], res["ipc_first"]["rid"])

        # SEC-003 by design: the request carries no filesystem path to substitute.
        self.assertNotIn("path", effect)
        self.assertNotIn("file", effect)

    def test_unauthenticated_peer_is_refused(self) -> None:
        # The parent is root (uid 0), which is NOT the allowed requester uid.
        _, grant = self._issue_grant("log.level", "debug")
        proposal_effect = {
            "resource": "config",
            "operation": "set",
            "key": "log.level",
            "value": "debug",
            "precondition": None,
        }
        resp = client_request(
            self.sock_path,
            {"effect": proposal_effect, "grant_token": grant.to_dict(), "request_id": "x"},
        )
        self.assertEqual(resp["outcome"], "REFUSED")
        self.assertIn("not authorized", resp["reason"])

    def test_wrong_effect_refused_over_ipc(self) -> None:
        # A valid grant for one effect, submitted with a different effect.
        proposal, grant = self._issue_grant("log.level", "info")
        other_effect = dict(proposal.effect)
        other_effect["value"] = "debug"  # different identity

        def act():
            return client_request(
                self.sock_path,
                {"effect": other_effect, "grant_token": grant.to_dict(), "request_id": "w"},
            )

        resp = self._run_as_requester(act)
        self.assertEqual(resp["outcome"], "REFUSED")


if __name__ == "__main__":
    unittest.main()
