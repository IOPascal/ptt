"""PTT wire protocol: line-based auth, then length-prefixed binary frames.

After the TLS handshake the client sends the token as one UTF-8 line.
The server answers with ``OK`` or ``DENIED`` (and closes on denial).

Everything after auth uses binary frames::

    +------+----------------+------------------+
    | type | length (u32BE) | payload (bytes)  |
    +------+----------------+------------------+

Frame types: STDIN (client->host), STDOUT (host->client),
RESIZE ``struct("!HH", cols, rows)`` (client->host),
EXIT ``struct("!i", returncode)`` (host->client).
"""
from __future__ import annotations

import struct

FRAME_STDIN = 0x01
FRAME_STDOUT = 0x02
FRAME_RESIZE = 0x03
FRAME_EXIT = 0x04

_HEADER = struct.Struct("!BI")
MAX_FRAME_SIZE = 1024 * 1024  # 1 MiB sanity limit
MAX_LINE = 1024


def send_frame(sock, ftype: int, payload: bytes) -> None:
    """Send one frame (blocking)."""
    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError("frame payload too large")
    sock.sendall(_HEADER.pack(ftype, len(payload)) + payload)


def _recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return bytes(buf)


def recv_frame(sock) -> tuple[int, bytes]:
    """Receive one frame (blocking). Raises ConnectionError on EOF."""
    header = _recv_exact(sock, _HEADER.size)
    ftype, length = _HEADER.unpack(header)
    if length > MAX_FRAME_SIZE:
        raise ConnectionError("frame too large, closing")
    payload = _recv_exact(sock, length) if length else b""
    return ftype, payload


def send_line(sock, line: str) -> None:
    sock.sendall(line.encode("utf-8") + b"\n")


def recv_line(sock) -> str:
    buf = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("connection closed during auth")
        if ch == b"\n":
            break
        buf += ch
        if len(buf) > MAX_LINE:
            raise ConnectionError("auth line too long")
    return bytes(buf).decode("utf-8", "replace")
