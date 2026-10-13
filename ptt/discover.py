"""LAN discovery: find PTT hosts without typing IP addresses.

The client broadcasts a discovery request on UDP; hosts answer with their
name, TCP port, auth kind, TLS fingerprint and busy flag. Target address
and port are injectable so tests can use loopback instead of real broadcast.
"""
from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Callable

DISCOVERY_PORT = 8023
DISCOVER_REQUEST = b"PTT_DISCOVER v1"
DISCOVER_TIMEOUT = 2.0
MAX_HOSTS = 64
MAX_FINGERPRINT_LEN = 256


def parse_reply(data: bytes, address: str) -> dict[str, object] | None:
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
    name = "".join(ch for ch in name_raw if ch.isprintable()).strip()[:64]
    if not 1 <= port <= 65535:
        return None
    if not fingerprint.startswith("SHA256:"):
        return None
    if len(fingerprint) > MAX_FINGERPRINT_LEN:
        return None
    if auth not in ("pin", "token"):
        return None
    return {
        "name": name or address,
        "address": address,
        "port": port,
        "fingerprint": fingerprint,
        "auth": auth,
        "busy": bool(info.get("busy", False)),
    }


def _sorted_hosts(found: dict[str, dict]) -> list[dict]:
    """Hosts sorted by name (case-insensitive)."""
    return sorted(found.values(), key=lambda h: h["name"].lower())


def _store_reply(found: dict[str, dict], info: dict) -> None:
    """Store one parsed reply, bounded to MAX_HOSTS entries."""
    if info["fingerprint"] in found or len(found) < MAX_HOSTS:
        found[info["fingerprint"]] = info


def discover(
    timeout: float = DISCOVER_TIMEOUT,
    target: str = "255.255.255.255",
    port: int = DISCOVERY_PORT,
) -> list[dict]:
    """Broadcast discovery and collect host replies. Never raises."""
    found: dict[str, dict] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        deadline = time.monotonic() + timeout
        next_send = 0.0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if time.monotonic() >= next_send:
                # re-send: UDP is lossy, and the responder may just be starting
                try:
                    sock.sendto(DISCOVER_REQUEST, (target, port))
                except OSError:
                    return _sorted_hosts(found)
                next_send = time.monotonic() + 0.5
            sock.settimeout(min(remaining, max(0.01, next_send - time.monotonic())))
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                time.sleep(0.05)  # e.g. ICMP unreachable: keep listening
                continue
            info = parse_reply(data, addr[0])
            if info is not None:
                _store_reply(found, info)
    finally:
        sock.close()
    return _sorted_hosts(found)


def make_reply(
    name: str, tcp_port: int, fingerprint: str, auth: str, busy: bool = False
) -> bytes:
    return json.dumps(
        {
            "ptt": 1,
            "name": name,
            "port": tcp_port,
            "fingerprint": fingerprint,
            "auth": auth,
            "busy": busy,
        }
    ).encode("utf-8")


def run_responder(
    stop: threading.Event,
    tcp_port: int,
    name: str,
    fingerprint: str,
    auth: str,
    port: int,
    busy: Callable[[], bool] | None = None,
) -> None:
    """Answer discovery requests until ``stop`` is set (runs in a thread).

    ``busy`` (when given) reports live occupancy per request.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError:
        return
    sock.settimeout(0.5)
    try:
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                break
            if data.strip() == DISCOVER_REQUEST:
                is_busy = False
                if busy is not None:
                    try:
                        is_busy = bool(busy())
                    except Exception:
                        is_busy = False
                try:
                    sock.sendto(
                        make_reply(name, tcp_port, fingerprint, auth, is_busy),
                        addr,
                    )
                except OSError:
                    pass
    finally:
        sock.close()


def start_responder(
    tcp_port: int,
    name: str,
    fingerprint: str,
    auth: str,
    port: int = DISCOVERY_PORT,
    busy: Callable[[], bool] | None = None,
) -> tuple[threading.Event, threading.Thread]:
    """Start the responder thread; returns (stop_event, thread)."""
    stop = threading.Event()
    thread = threading.Thread(
        target=run_responder,
        args=(stop, tcp_port, name, fingerprint, auth, port, busy),
        daemon=True,
    )
    thread.start()
    return stop, thread
