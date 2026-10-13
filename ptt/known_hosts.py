"""TOFU store for host fingerprints (direct connections).

The first direct connection to a host stores its TLS fingerprint; later
connections abort when the fingerprint changed (possible attack). Discovery
connections keep comparing against the announced fingerprint instead.
"""
from __future__ import annotations

import json
import os

from .cert import default_cert_dir, ensure_data_dir, secure_write

KNOWN_HOSTS_FILE = "known_hosts"


def known_hosts_path(data_dir: str | None = None) -> str:
    """Path of the TOFU file (defaults to ``~/.ptt/known_hosts``)."""
    return os.path.join(data_dir or default_cert_dir(), KNOWN_HOSTS_FILE)


def _load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def get_fingerprint(host: str, port: int, path: str | None = None) -> str | None:
    """Stored fingerprint for ``host:port``, or None when unknown."""
    entry = _load(path or known_hosts_path()).get(f"{host}:{port}")
    return entry if isinstance(entry, str) else None


def store_fingerprint(
    host: str, port: int, fingerprint: str, path: str | None = None
) -> None:
    """Remember ``fingerprint`` for ``host:port`` (TOFU)."""
    file_path = path or known_hosts_path()
    ensure_data_dir(os.path.dirname(file_path))
    data = _load(file_path)
    data[f"{host}:{port}"] = fingerprint
    payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
    secure_write(file_path, payload)
