"""Authenticated IPC between an untrusted requester and the protected owner.

This is the only channel through which a requester may ask the resource owner to
act. It is a Unix domain socket, which lets the owner authenticate the peer at
the kernel level via `SO_PEERCRED` — the connecting process's uid/gid/pid as the
kernel sees them, which the peer cannot forge.

Two responsibilities live here and nothing else:

* **Framing** — length-prefixed JSON, so messages have exact boundaries.
* **Peer credentials** — `peer_credentials` reads the authenticated identity of
  whoever connected.

Authorization of that identity is the owner service's job, not this module's.
"""

from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass

_LEN = struct.Struct("!I")
_UCRED = struct.Struct("iII")  # struct ucred: pid (int), uid, gid (unsigned)
_MAX = 1 << 20  # 1 MiB cap on a single message


@dataclass(frozen=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


def peer_credentials(conn: socket.socket) -> PeerCredentials:
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
    pid, uid, gid = _UCRED.unpack(raw)
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def send_msg(conn: socket.socket, obj: dict) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(body) > _MAX:
        raise ValueError("message too large")
    conn.sendall(_LEN.pack(len(body)) + body)


def _recv_exactly(conn: socket.socket, n: int) -> bytes:
    chunks = []
    got = 0
    while got < n:
        chunk = conn.recv(n - got)
        if not chunk:
            raise ConnectionError("peer closed mid-message")
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def recv_msg(conn: socket.socket) -> dict:
    (length,) = _LEN.unpack(_recv_exactly(conn, _LEN.size))
    if length > _MAX:
        raise ValueError("declared message too large")
    return json.loads(_recv_exactly(conn, length).decode("utf-8"))


def client_request(sock_path: str, request: dict, *, timeout: float = 10.0) -> dict:
    """Connect to the owner, send one request, return its one response."""
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(timeout)
    try:
        conn.connect(sock_path)
        send_msg(conn, request)
        return recv_msg(conn)
    finally:
        conn.close()
