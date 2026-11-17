"""The protected resource owner as a standalone service under its own identity.

In production this process runs as a dedicated operating-system user. The
protected database lives in a directory that only that user can enter (mode
0700), so no other process — whatever it is running as — can open the database
file, its WAL, or its temporaries. The *only* way to change protected state is to
connect to this service's socket and present a valid grant.

The service does three things on each connection:

1. Authenticate the peer with `SO_PEERCRED` and check its uid against the allowed
   set. An unrecognized peer is refused before any request is read.
2. Hand the request to the in-process `ResourceOwner`, which performs the full
   grant verification and effect-bound, single-use application.
3. Return a classified outcome. The requester never gets a file handle, a key, or
   any path it can use to reach the database directly.

The requester chooses an *operation and value*, never a filesystem path: the
owner maps the logical resource to its own fixed database location. That removes
path-substitution and symlink attacks by construction — there is no
client-supplied path to substitute.
"""

from __future__ import annotations

import json
import os
import socket
from typing import Iterable

from vgi.crypto import KeyPair, VerifyKey
from vgi.execution.freshness import FreshnessAuthority
from vgi.execution.ipc import PeerCredentials, peer_credentials, recv_msg, send_msg
from vgi.execution.resource_owner import AuthorizationError, RecoveryBlocked, ResourceOwner

KEYFILE_NAME = "owner_keys.json"


def write_keyfile(secret_dir: str, *, executor: KeyPair, authority_pub: VerifyKey) -> str:
    path = os.path.join(secret_dir, KEYFILE_NAME)
    with open(path, "w") as f:
        json.dump(
            {"executor_priv": executor.private_hex(), "authority_pub": authority_pub.to_hex()},
            f,
        )
    os.chmod(path, 0o600)
    return path


def build_owner(secret_dir: str, *, resource_db: str, freshness_db: str) -> ResourceOwner:
    """Reconstruct the resource owner inside the owner process from its keyfile."""
    with open(os.path.join(secret_dir, KEYFILE_NAME)) as f:
        km = json.load(f)
    freshness = FreshnessAuthority(freshness_db)
    return ResourceOwner(
        resource_db,
        executor_key=KeyPair.from_hex(km["executor_priv"]),
        authority_verify_key=VerifyKey.from_hex(km["authority_pub"]),
        freshness=freshness,
    )


_REQUEST_FIELDS = {"effect", "grant_token", "request_id"}
_CONN_TIMEOUT = 10.0


def _classify(outcome: str) -> str:
    # Minimal mapping; the full Outcome Resolver (EXE-06) refines UNKNOWN/CONFLICT.
    return {"applied": "COMMITTED", "duplicate": "COMMITTED", "rejected": "REFUSED"}.get(
        outcome, "REFUSED"
    )


class OwnerService:
    def __init__(
        self,
        sock_path: str,
        resource_owner: ResourceOwner,
        *,
        allowed_uids: Iterable[int],
    ):
        self._sock_path = sock_path
        self._owner = resource_owner
        self._allowed = set(allowed_uids)

    def _handle(self, conn: socket.socket) -> None:
        peer: PeerCredentials = peer_credentials(conn)
        if peer.uid not in self._allowed:
            # Authenticated-but-unauthorized peer. Refuse before reading anything.
            send_msg(
                conn,
                {"outcome": "REFUSED", "reason": "peer uid not authorized", "peer_uid": peer.uid},
            )
            return

        try:
            request = recv_msg(conn)
        except ValueError:  # bad framing, oversize, invalid JSON / UTF-8
            send_msg(conn, {"outcome": "REFUSED", "reason": "malformed message"})
            return

        # Strict envelope: an object with only the known fields.
        if not isinstance(request, dict) or not set(request) <= _REQUEST_FIELDS:
            send_msg(conn, {"outcome": "REFUSED", "reason": "malformed request"})
            return
        request_id = request.get("request_id")
        if request_id is not None and not isinstance(request_id, str):
            send_msg(conn, {"outcome": "REFUSED", "reason": "malformed request_id"})
            return

        try:
            signed = self._owner.redeem_and_apply(
                {"effect": request.get("effect"), "grant_token": request.get("grant_token")}
            )
        except RecoveryBlocked as e:
            # Prior execution cannot be determined: say so, never claim REFUSED.
            send_msg(conn, {"outcome": "UNKNOWN", "reason": str(e), "request_id": request_id})
            return
        except AuthorizationError as e:
            send_msg(conn, {"outcome": "REFUSED", "reason": str(e), "request_id": request_id})
            return
        except Exception:
            # An internal failure may have happened after a commit, so the honest
            # answer is UNKNOWN; the durable record decides on retry.
            send_msg(
                conn,
                {
                    "outcome": "UNKNOWN",
                    "reason": "internal error; outcome undetermined",
                    "request_id": request_id,
                },
            )
            return

        send_msg(
            conn,
            {
                "outcome": _classify(signed.receipt["outcome"]),
                "receipt_outcome": signed.receipt["outcome"],
                "receipt": signed.to_dict(),
                "request_id": request_id,
            },
        )

    def serve_forever(self, stop_event=None) -> None:
        """Serve until `stop_event` (a threading.Event) is set, or forever.

        A single connection can never terminate the loop: every per-connection
        failure is contained, and each connection has a read timeout so a peer
        that connects and stalls cannot hold the service indefinitely.
        """
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if os.path.exists(self._sock_path):
            os.unlink(self._sock_path)
        srv.bind(self._sock_path)
        os.chmod(self._sock_path, 0o777)  # peers may connect; auth is via SO_PEERCRED
        srv.listen(16)
        srv.settimeout(0.2)
        try:
            while stop_event is None or not stop_event.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                conn.settimeout(_CONN_TIMEOUT)
                try:
                    self._handle(conn)
                except Exception:
                    pass  # contained: one bad connection never stops the service
                finally:
                    conn.close()
        finally:
            srv.close()
            if os.path.exists(self._sock_path):
                os.unlink(self._sock_path)
