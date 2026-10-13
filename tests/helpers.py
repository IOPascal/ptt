"""Shared helpers for the PTT test-suite (ports, TLS, shell sessions)."""
import socket
import struct
import time

from ptt.cert import tls_client_context
from ptt.protocol import recv_frame, send_frame
from ptt.protocol import FRAME_EXIT, FRAME_RESIZE, FRAME_STDIN, FRAME_STDOUT


def _free_tcp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _free_udp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def tls_connect(port: int, alpn=None):
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    context = tls_client_context(alpn)
    sock = context.wrap_socket(raw, server_hostname="127.0.0.1")
    sock.settimeout(10)
    return sock


def wait_for_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            probe = socket.create_connection(("127.0.0.1", port), timeout=1)
            probe.close()
            return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("host did not start listening")


def echo_and_exit(sock, marker: str):
    """Run `echo <marker>` then `exit`; returns (output, exit_code)."""
    send_frame(sock, FRAME_RESIZE, struct.pack("!HH", 80, 24))
    send_frame(sock, FRAME_STDIN, f"echo {marker}\n".encode())
    seen = b""
    exit_code = None
    exit_sent = False
    while exit_code is None:
        ftype, payload = recv_frame(sock)
        if ftype == FRAME_STDOUT:
            seen += payload
            # send exactly once: the PTY echoes `exit` back, and a second
            # send would race the server closing the connection
            if not exit_sent and marker.encode() in seen:
                send_frame(sock, FRAME_STDIN, b"exit\n")
                exit_sent = True
        elif ftype == FRAME_EXIT:
            (exit_code,) = struct.unpack("!i", payload)
    return seen, exit_code
