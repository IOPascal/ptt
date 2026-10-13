"""PTT wire protocol: line-based auth, then length-prefixed binary frames.

After the TLS handshake the client sends the token as one UTF-8 line.
The server answers with ``OK``, ``DENIED`` or ``BUSY`` (and closes
unless the answer is ``OK``).

Everything after auth uses binary frames::

    +------+----------------+------------------+
    | type | length (u32BE) | payload (bytes)  |
    +------+----------------+------------------+

Frame types: STDIN (client->host), STDOUT (host->client),
RESIZE ``struct("!HH", cols, rows)`` (client->host),
EXIT ``struct("!i", returncode)`` (host->client, see ``send_exit``).

Transfer mode (negotiated via TLS ALPN, see ``ptt.transfer``) uses
TREQ/TACK/TDATA/TDONE/TERR instead of a shell.
"""
from __future__ import annotations

import socket
import struct
import sys

FRAME_STDIN = 0x01
FRAME_STDOUT = 0x02
FRAME_RESIZE = 0x03
FRAME_EXIT = 0x04
FRAME_TREQ = 0x10
FRAME_TACK = 0x11
FRAME_TDATA = 0x12
FRAME_TDONE = 0x13
FRAME_TERR = 0x14

ALPN_SHELL = "ptt1-shell"
ALPN_TRANSFER = "ptt1-transfer"

_HEADER = struct.Struct("!BI")
MAX_FRAME_SIZE = 1024 * 1024  # 1 MiB sanity limit
MAX_LINE = 1024
MAX_UNKNOWN_FRAMES = 10  # tolerated unknown frame types per connection

KEEPALIVE_AFTER = 60.0  # idle seconds before the first keepalive probe
KEEPALIVE_INTERVAL = 10.0  # seconds between probes (where tunable)


def enable_keepalive(
    sock,
    after: float = KEEPALIVE_AFTER,
    interval: float = KEEPALIVE_INTERVAL,
) -> None:
    """Enable TCP keepalive so dead peers surface as socket errors.

    Uses short timers where the OS allows it (Linux/macOS/Windows);
    always fails soft: plain SO_KEEPALIVE or nothing on odd platforms.
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        return
    try:
        if sys.platform == "win32":
            sock.ioctl(
                socket.SIO_KEEPALIVE_VALS,
                (1, int(after * 1000), int(interval * 1000)),
            )
        elif sys.platform == "darwin":
            keepalive = getattr(socket, "TCP_KEEPALIVE", 0x10)
            sock.setsockopt(socket.IPPROTO_TCP, keepalive, int(after))
        else:
            for name, value in (
                ("TCP_KEEPIDLE", int(after)),
                ("TCP_KEEPINTVL", int(interval)),
                ("TCP_KEEPCNT", 3),
            ):
                const = getattr(socket, name, None)
                if const is not None:
                    sock.setsockopt(socket.IPPROTO_TCP, const, value)
    except OSError:
        pass

_KNOWN_FRAMES = frozenset(
    {
        FRAME_STDIN,
        FRAME_STDOUT,
        FRAME_RESIZE,
        FRAME_EXIT,
        FRAME_TREQ,
        FRAME_TACK,
        FRAME_TDATA,
        FRAME_TDONE,
        FRAME_TERR,
    }
)


class UnknownFrameError(ConnectionError):
    """Peer sent a frame type outside the known range."""


def send_frame(sock: socket.socket, ftype: int, payload: bytes) -> None:
    """Send one frame (blocking)."""
    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError("frame payload too large")
    sock.sendall(_HEADER.pack(ftype, len(payload)) + payload)


def send_exit(sock: socket.socket, code: int) -> None:
    """Send the EXIT frame with a return code (blocking)."""
    send_frame(sock, FRAME_EXIT, struct.pack("!i", code))


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return bytes(buf)


def recv_frame(sock: socket.socket) -> tuple[int, bytes]:
    """Receive one frame (blocking).

    Raises ConnectionError on EOF and UnknownFrameError for frame types
    outside the known range (extend ``_KNOWN_FRAMES`` when adding types).
    """
    header = _recv_exact(sock, _HEADER.size)
    ftype, length = _HEADER.unpack(header)
    if length > MAX_FRAME_SIZE:
        raise ConnectionError("frame too large, closing")
    payload = _recv_exact(sock, length) if length else b""
    if ftype not in _KNOWN_FRAMES:
        raise UnknownFrameError(f"unknown frame type {ftype:#x}")
    return ftype, payload


def send_line(sock: socket.socket, line: str) -> None:
    sock.sendall(line.encode("utf-8") + b"\n")


def recv_line(sock: socket.socket) -> str:
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
    # Tolerate CRLF line endings (e.g. from minimal TCP clients).
    return bytes(buf).decode("utf-8", "replace").removesuffix("\r")
