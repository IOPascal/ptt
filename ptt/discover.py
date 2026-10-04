"""LAN discovery: find PTT hosts without typing IP addresses.

The client broadcasts a discovery request on UDP; hosts answer with their
name, TCP port, auth kind and TLS fingerprint. Target address and port are
injectable so tests can use loopback instead of real broadcast.
"""
from __future__ import annotations

import json
import socket
import threading
import time

DISCOVERY_PORT = 8023
DISCOVER_REQUEST = b"PTT_DISCOVER v1"
DISCOVER_TIMEOUT = 2.0


def parse_reply(data: bytes, address: str) -> dict | None:
    """Parse one discovery reply; None if malformed."""
    try:
        info = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(info, dict):
        return None
    try:
        name_raw = info["name"]
        port = int(info["port"])
        fingerprint = str(info["fingerprint"])
        auth = str(info["auth"])
    except (KeyError, TypeError, ValueError):
        return None
    if not isinstance(name_raw, str):
        return None
    name = name_raw[:64]
    if not 1 <= port <= 65535:
        return None
    if not fingerprint.startswith("SHA256:"):
        return None
    if auth not in ("pin", "token"):
        return None
    return {
        "name": name or address,
        "address": address,
        "port": port,
        "fingerprint": fingerprint,
        "auth": auth,
    }


def discover(
    timeout: float = DISCOVER_TIMEOUT,
    target: str = "255.255.255.255",
    port: int = DISCOVERY_PORT,
) -> list:
    """Broadcast discovery and collect host replies. Never raises."""
    found: dict[str, dict] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.sendto(DISCOVER_REQUEST, (target, port))
        except OSError:
            return []
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                break
            info = parse_reply(data, addr[0])
            if info is not None:
                found[info["fingerprint"]] = info
    finally:
        sock.close()
    return sorted(found.values(), key=lambda h: h["name"].lower())


def make_reply(name: str, tcp_port: int, fingerprint: str, auth: str) -> bytes:
    return json.dumps(
        {
            "ptt": 1,
            "name": name,
            "port": tcp_port,
            "fingerprint": fingerprint,
            "auth": auth,
        }
    ).encode("utf-8")


def run_responder(
    stop, tcp_port: int, name: str, fingerprint: str, auth: str, port: int
) -> None:
    """Answer discovery requests until ``stop`` is set (runs in a thread)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError:
        return
    sock.settimeout(0.5)
    reply = make_reply(name, tcp_port, fingerprint, auth)
    try:
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                break
            if data.strip() == DISCOVER_REQUEST:
                try:
                    sock.sendto(reply, addr)
                except OSError:
                    pass
    finally:
        sock.close()


def start_responder(
    tcp_port: int, name: str, fingerprint: str, auth: str, port: int = DISCOVERY_PORT
):
    """Start the responder thread; returns (stop_event, thread)."""
    stop = threading.Event()
    thread = threading.Thread(
        target=run_responder,
        args=(stop, tcp_port, name, fingerprint, auth, port),
        daemon=True,
    )
    thread.start()
    return stop, thread
