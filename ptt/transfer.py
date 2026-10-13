"""File transfer over the PTT tunnel (mode negotiated via TLS ALPN).

After auth, transfer clients (ALPN ``ptt1-transfer``) exchange request /
data / done frames instead of starting a shell. Hosts without transfer
support negotiate no ALPN protocol, so clients fail cleanly before
sending anything.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import socket
import time

from .output import TIMEOUT_MESSAGE, err, format_bytes, info, ok
from .protocol import (
    ALPN_TRANSFER,
    FRAME_TACK,
    FRAME_TDATA,
    FRAME_TDONE,
    FRAME_TERR,
    FRAME_TREQ,
    MAX_UNKNOWN_FRAMES,
    UnknownFrameError,
    recv_frame,
    send_frame,
)

MAX_TREQ_PATH = 1024
TRANSFER_CHUNK_SIZE = 64 * 1024
TRANSFER_ACK_TIMEOUT = 10.0
TRANSFER_TICK = 1.0
PART_SUFFIX = ".ptt-part"

_SIZE_SUFFIXES = {"K": 1024, "M": 1024**2, "G": 1024**3}


def parse_size(text: str) -> int:
    """Parse ``1024``, ``100K``, ``1.5M`` or ``2G`` into bytes."""
    cleaned = text.strip()
    if not cleaned:
        raise ValueError("leere Größe")
    suffix = cleaned[-1].upper()
    if suffix in _SIZE_SUFFIXES:
        num, mult = cleaned[:-1], _SIZE_SUFFIXES[suffix]
    else:
        num, mult = cleaned, 1
    try:
        value = float(num)
    except ValueError:
        raise ValueError(f"ungültige Größe: {text!r}") from None
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"Größe darf nicht negativ sein: {text!r}")
    return int(value * mult)


class _TransferLimits:
    """Transfer size/timeout policy plus live activity state."""

    def __init__(
        self, max_size: int = 0, idle_seconds: float = 0.0,
        max_seconds: float = 0.0,
    ) -> None:
        self.max_size = max(0, max_size)
        self.idle_seconds = max(0.0, idle_seconds)
        self.max_seconds = max(0.0, max_seconds)
        now = time.monotonic()
        self.started = now
        self.last_active = now

    def touch(self) -> None:
        self.last_active = time.monotonic()

    def hit(self) -> str | None:
        """``idle``/``expired`` when a session timeout fired, else None."""
        now = time.monotonic()
        if self.max_seconds > 0 and now - self.started > self.max_seconds:
            return "expired"
        if self.idle_seconds > 0 and now - self.last_active > self.idle_seconds:
            return "idle"
        return None

    def too_big(self, size: int) -> bool:
        return self.max_size > 0 and size > self.max_size

    def too_big_reason(self) -> str:
        return f"Datei zu groß (max. {format_bytes(self.max_size)})"


def _hit_reason(hit: str) -> str:
    return "Inaktivität" if hit == "idle" else "maximale Sitzungsdauer erreicht"


class TransferError(Exception):
    """File transfer failed; the message is user-facing (German)."""


class TransferTimeoutError(TransferError):
    """Transfer aborted because --timeout expired (exit code 124)."""


def _json_dict(payload: bytes) -> dict | None:
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def _terr_text(payload: bytes) -> str:
    return payload.decode("utf-8", "replace")[:200] or "abgebrochen"


def _send_terr(conn, reason: str) -> None:
    try:
        send_frame(conn, FRAME_TERR, reason.encode("utf-8"))
    except OSError:
        pass


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


#: Age after which an interrupted transfer's ``.ptt-part`` file is
#: considered abandoned and removed at host startup.
STALE_PART_MAX_AGE = 24 * 3600


def cleanup_stale_parts(root: str, max_age: float = STALE_PART_MAX_AGE) -> int:
    """Remove abandoned ``.ptt-part`` files below ``root``.

    Only regular files ending in ``PART_SUFFIX`` whose mtime is older
    than ``max_age`` seconds are removed; symlinks are never followed.
    Returns the number of removed files.
    """
    if not os.path.isdir(root):
        return 0
    cutoff = time.time() - max_age
    removed = 0
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            if not name.endswith(PART_SUFFIX):
                continue
            path = os.path.join(dirpath, name)
            try:
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                if os.path.getmtime(path) > cutoff:
                    continue
                os.remove(path)
            except OSError:
                continue
            removed += 1
    return removed


# Failure reasons proving the partial file itself is bad: a retry must start
# clean instead of stacking new bytes onto a corrupt prefix. Any other
# failure (dropped connection, shutdown, timeout) keeps the .ptt-part so the
# next attempt resumes where this one stopped.
_BAD_PART_PREFIXES = (
    "mehr Daten als angekündigt",
    "Prüfsumme falsch",
    "unvollständig",
    "Schreiben fehlgeschlagen",
    "Protokollfehler",
    "Datei zu groß",
    "Zieldatei kann nicht",
    "Zieldatei nicht schreibbar",
    "Lesen fehlgeschlagen",
    "ist ein Verzeichnis",
    "Datei nicht gefunden",
    "Datei nicht lesbar",
    "ungültiger Pfad",
    "ungültige ",
)


def _bad_part(reason: str) -> bool:
    """True when ``reason`` forbids resuming from the partial file."""
    return reason.startswith(_BAD_PART_PREFIXES)


def _clamp_offset(offset, size) -> int:
    """Clamp a peer-supplied resume offset into ``[0, size]``."""
    try:
        value = int(offset)
    except (TypeError, ValueError):
        return 0
    if value < 0:
        return 0
    if size is not None and value > size:
        return size
    return value


def _hash_prefix(path: str, length: int):
    """SHA-256 over the first ``length`` bytes; None when unreadable."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            remaining = length
            while remaining > 0:
                chunk = handle.read(min(TRANSFER_CHUNK_SIZE, remaining))
                if not chunk:
                    return None
                digest.update(chunk)
                remaining -= len(chunk)
    except OSError:
        return None
    return digest


_WIN_RESERVED = frozenset(
    ["con", "prn", "aux", "nul"]
    + [f"com{i}" for i in range(1, 10)]
    + [f"lpt{i}" for i in range(1, 10)]
)


def _win_part_ok(part: str) -> bool:
    """One path component acceptable on Windows (no ADS/reserved/trailing)."""
    if ":" in part:
        return False
    if part.lower().split(".")[0] in _WIN_RESERVED:
        return False
    if part != "." and (part.endswith(" ") or part.endswith(".")):
        return False
    return True


def _target_path(root: str, name: str) -> str | None:
    """Resolve ``name`` inside ``root``; None when it would escape."""
    if not name or "\x00" in name or os.path.isabs(name):
        return None
    parts = [name]
    seps = {os.sep}
    if os.altsep:
        seps.add(os.altsep)
    for sep in seps:
        parts = [p for part in parts for p in part.split(sep)]
    if any(part == ".." for part in parts):
        return None
    if os.name == "nt" and not all(_win_part_ok(p) for p in parts):
        return None
    base = os.path.realpath(root)
    target = os.path.realpath(os.path.join(root, name))
    if target == base or not target.startswith(base + os.sep):
        return None
    return target


def _expired(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() > deadline


def _phase_timeout(deadline: float | None, cap: float) -> float:
    """Socket timeout for one phase: phase cap, cut by the deadline."""
    if deadline is None:
        return cap
    return max(0.1, min(cap, deadline - time.monotonic()))


def _recv_or_raise(sock, what: str, deadline: float | None = None):
    try:
        return recv_frame(sock)
    except socket.timeout as exc:
        # 50 ms grace: the socket timeout may fire a hair early.
        if deadline is not None and time.monotonic() >= deadline - 0.05:
            raise TransferTimeoutError(TIMEOUT_MESSAGE) from None
        raise TransferError(f"{what}: {exc}") from exc
    except (OSError, ValueError, UnknownFrameError) as exc:
        raise TransferError(f"{what}: {exc}") from exc


def _valid_size(size: object) -> bool:
    return isinstance(size, int) and not isinstance(size, bool) and size >= 0


def _valid_sha(sha: object) -> bool:
    if not isinstance(sha, str) or len(sha) != 64:
        return False
    try:
        return len(bytes.fromhex(sha)) == 32
    except ValueError:
        return False


def encode_treq(
    op: str,
    path: str,
    size: int | None = None,
    sha256: str | None = None,
    resume: bool = False,
    offset: int = 0,
) -> bytes:
    """Encode a transfer request (``op`` is ``put`` or ``get``)."""
    if op not in ("put", "get"):
        raise ValueError(f"op muss 'put' oder 'get' sein: {op!r}")
    if not isinstance(path, str) or not path or len(path) > MAX_TREQ_PATH:
        raise ValueError(f"ungültiger Pfad: {path!r}")
    if size is not None and not _valid_size(size):
        raise ValueError(f"ungültige Größe: {size!r}")
    if sha256 is not None and not _valid_sha(sha256):
        raise ValueError(f"ungültiges SHA-256: {sha256!r}")
    if not isinstance(resume, bool):
        raise ValueError(f"resume muss bool sein: {resume!r}")
    if not _valid_size(offset):
        raise ValueError(f"ungültiger Offset: {offset!r}")
    return json.dumps(
        {
            "op": op,
            "path": path,
            "size": size,
            "sha256": sha256,
            "resume": resume,
            "offset": offset,
        }
    ).encode("utf-8")


def decode_treq(payload: bytes) -> dict | None:
    """Decode a transfer request; None when malformed."""
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    op, path = doc.get("op"), doc.get("path")
    size, sha256 = doc.get("size"), doc.get("sha256")
    resume, offset = doc.get("resume", False), doc.get("offset", 0)
    if op not in ("put", "get"):
        return None
    if not isinstance(path, str) or not path or len(path) > MAX_TREQ_PATH:
        return None
    if size is not None and not _valid_size(size):
        return None
    if sha256 is not None and not _valid_sha(sha256):
        return None
    if not isinstance(resume, bool):
        return None
    if not _valid_size(offset):
        return None
    return {
        "op": op,
        "path": path,
        "size": size,
        "sha256": sha256,
        "resume": resume,
        "offset": offset,
    }


def encode_tack(
    ok: bool, reason: str = "", size: int | None = None, offset: int = 0
) -> bytes:
    """Encode a transfer reply (accept with ``ok``, else ``reason``)."""
    if not isinstance(ok, bool):
        raise ValueError(f"ok muss bool sein: {ok!r}")
    if not isinstance(reason, str):
        raise ValueError(f"reason muss str sein: {reason!r}")
    if size is not None and not _valid_size(size):
        raise ValueError(f"ungültige Größe: {size!r}")
    if not _valid_size(offset):
        raise ValueError(f"ungültiger Offset: {offset!r}")
    return json.dumps(
        {"ok": ok, "reason": reason, "size": size, "offset": offset}
    ).encode("utf-8")


def decode_tack(payload: bytes) -> dict | None:
    """Decode a transfer reply; None when malformed."""
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    accepted = doc.get("ok")
    reason, size = doc.get("reason", ""), doc.get("size")
    offset = doc.get("offset", 0)
    if not isinstance(accepted, bool):
        return None
    if not isinstance(reason, str):
        return None
    if size is not None and not _valid_size(size):
        return None
    if not _valid_size(offset):
        return None
    return {"ok": accepted, "reason": reason, "size": size, "offset": offset}


def wants_transfer(sock) -> bool:
    """True when the peer negotiated transfer mode via ALPN."""
    selected = getattr(sock, "selected_alpn_protocol", lambda: None)()
    return selected == ALPN_TRANSFER


def _send_frame_or_raise(sock, ftype: int, payload: bytes, what: str) -> None:
    try:
        send_frame(sock, ftype, payload)
    except OSError as exc:
        raise TransferError(f"{what}: {exc}") from exc


def _serve_put(conn, root, req, peer_name, marks, shutdown, lim) -> None:
    ok_mark, err_mark, info_mark = marks
    name = req["path"]
    target = _target_path(root, name)
    if target is None:
        print(
            f"{err_mark} Transfer put {name!r} von {peer_name} "
            "abgelehnt (ungültiger Pfad).",
            flush=True,
        )
        _send_terr(conn, "ungültiger Pfad")
        return
    if req["size"] is not None and lim.too_big(req["size"]):
        print(
            f"{err_mark} Transfer put {name!r} von {peer_name} "
            "abgelehnt (zu groß).",
            flush=True,
        )
        try:
            send_frame(conn, FRAME_TACK, encode_tack(False, lim.too_big_reason()))
        except OSError:
            pass
        return
    try:
        parent = os.path.dirname(target)
        if parent:
            os.makedirs(parent, exist_ok=True)
    except OSError:
        _send_terr(conn, "Zielverzeichnis nicht erstellbar")
        return
    tmp = target + PART_SUFFIX
    offset = 0
    if req["resume"] and os.path.isfile(tmp):
        try:
            offset = os.path.getsize(tmp)
        except OSError:
            offset = 0
        if req["size"] is not None and offset > req["size"]:
            _remove_quietly(tmp)
            offset = 0
    digest = hashlib.sha256()
    if offset:
        digest = _hash_prefix(tmp, offset)
        if digest is None:
            digest = hashlib.sha256()
            _remove_quietly(tmp)
            offset = 0
    try:
        out = open(tmp, "ab" if offset else "wb")
    except OSError:
        _send_terr(conn, "Zieldatei nicht schreibbar")
        return
    try:
        send_frame(conn, FRAME_TACK, encode_tack(True, offset=offset))
    except OSError:
        out.close()
        if not offset:
            _remove_quietly(tmp)
        return
    if offset:
        print(
            f"{info_mark} Transfer put {name!r} von {peer_name}: "
            f"setze bei {format_bytes(offset)} fort.",
            flush=True,
        )
    received = offset
    done = False
    reason = "Verbindung abgebrochen"
    try:
        while True:
            if shutdown is not None and shutdown.is_set():
                reason = "Host fährt herunter"
                break
            try:
                ftype, payload = recv_frame(conn)
            except UnknownFrameError:
                reason = "Protokollfehler"
                break
            except socket.timeout:
                hit = lim.hit()
                if hit is None:
                    continue
                reason = _hit_reason(hit)
                break
            except (OSError, ValueError):
                break
            lim.touch()
            if ftype == FRAME_TDATA:
                try:
                    out.write(payload)
                    # Crash-honest resume offset: a SIGTERM right after
                    # this chunk must find it in the .ptt-part file.
                    out.flush()
                except OSError:
                    reason = "Schreiben fehlgeschlagen"
                    break
                digest.update(payload)
                received += len(payload)
                if lim.too_big(received):
                    reason = lim.too_big_reason()
                    break
                if req["size"] is not None and received > req["size"]:
                    reason = "mehr Daten als angekündigt"
                    break
            elif ftype == FRAME_TDONE:
                commit = _json_dict(payload)
                sha = commit.get("sha256") if commit else None
                computed = digest.hexdigest()
                if req["size"] is not None and received != req["size"]:
                    reason = (
                        f"unvollständig ({received} von {req['size']} B)"
                    )
                elif req["sha256"] is not None and computed != req["sha256"]:
                    reason = "Prüfsumme falsch"
                elif sha is not None and computed != sha:
                    reason = "Prüfsumme falsch"
                else:
                    out.close()
                    out = None
                    try:
                        os.replace(tmp, target)
                    except OSError:
                        reason = "Zieldatei kann nicht geschrieben werden"
                        break
                    done = True
                break
            elif ftype == FRAME_TERR:
                reason = _terr_text(payload)
                break
            # stray frames are ignored
    finally:
        if out is not None:
            out.close()
        if not done and _bad_part(reason):
            _remove_quietly(tmp)
    if done:
        print(
            f"{ok_mark} Transfer put {name!r} von {peer_name}: "
            f"ok ({format_bytes(received)}).",
            flush=True,
        )
        result = {"ok": True, "reason": ""}
    else:
        print(
            f"{err_mark} Transfer put {name!r} von {peer_name} "
            f"fehlgeschlagen: {reason}",
            flush=True,
        )
        result = {"ok": False, "reason": reason}
    try:
        send_frame(conn, FRAME_TDONE, json.dumps(result).encode("utf-8"))
    except OSError:
        pass


def _serve_get(conn, root, req, peer_name, marks, shutdown, lim) -> None:
    ok_mark, err_mark, _info_mark = marks
    name = req["path"]
    target = _target_path(root, name)
    if target is None:
        print(
            f"{err_mark} Transfer get {name!r} von {peer_name} "
            "abgelehnt (ungültiger Pfad).",
            flush=True,
        )
        _send_terr(conn, "ungültiger Pfad")
        return
    if os.path.isdir(target):
        _send_terr(conn, "ist ein Verzeichnis")
        return
    if not os.path.isfile(target):
        _send_terr(conn, "Datei nicht gefunden")
        return
    try:
        size = os.path.getsize(target)
        if lim.too_big(size):
            _send_terr(conn, lim.too_big_reason())
            return
        digest = hashlib.sha256()
        with open(target, "rb") as src:
            while True:
                chunk = src.read(TRANSFER_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        _send_terr(conn, "Datei nicht lesbar")
        return
    offset = _clamp_offset(req["offset"], size) if req["resume"] else 0
    try:
        send_frame(
            conn,
            FRAME_TACK,
            encode_tack(True, size=size, offset=offset),
        )
    except OSError:
        return
    sent = offset
    try:
        with open(target, "rb") as src:
            if offset:
                src.seek(offset)
            while True:
                if shutdown is not None and shutdown.is_set():
                    _send_terr(conn, "Host fährt herunter")
                    return
                hit = lim.hit()
                if hit is not None:
                    _send_terr(conn, _hit_reason(hit))
                    return
                try:
                    chunk = src.read(TRANSFER_CHUNK_SIZE)
                except OSError:
                    _send_terr(conn, "Lesen fehlgeschlagen")
                    return
                if not chunk:
                    break
                try:
                    send_frame(conn, FRAME_TDATA, chunk)
                except OSError:
                    return
                sent += len(chunk)
                lim.touch()
                if lim.too_big(sent):
                    _send_terr(conn, lim.too_big_reason())
                    return
        commit = json.dumps({"sha256": digest.hexdigest()}).encode("utf-8")
        send_frame(conn, FRAME_TDONE, commit)
    except OSError:
        return
    deadline = time.monotonic() + TRANSFER_ACK_TIMEOUT
    ftype, payload = None, b""
    while True:
        if shutdown is not None and shutdown.is_set():
            return
        try:
            ftype, payload = recv_frame(conn)
            break
        except UnknownFrameError:
            break
        except socket.timeout:
            if lim.hit() is not None or time.monotonic() > deadline:
                print(
                    f"{err_mark} Transfer get {name!r} von {peer_name}: "
                    "keine Bestätigung.",
                    flush=True,
                )
                return
        except (OSError, ValueError):
            print(
                f"{err_mark} Transfer get {name!r} von {peer_name}: "
                "keine Bestätigung.",
                flush=True,
            )
            return
    lim.touch()
    result = _json_dict(payload) if ftype == FRAME_TDONE else None
    if result is not None and result.get("ok") is True:
        print(
            f"{ok_mark} Transfer get {name!r} von {peer_name}: "
            f"ok ({format_bytes(size)}).",
            flush=True,
        )
    else:
        reason = result.get("reason") if result else "abgebrochen"
        print(
            f"{err_mark} Transfer get {name!r} von {peer_name} "
            f"fehlgeschlagen: {reason}",
            flush=True,
        )


def serve_transfer(
    conn,
    root: str,
    peer_name: str,
    color: bool,
    shutdown=None,
    max_size: int = 0,
    idle_seconds: float = 0.0,
    max_seconds: float = 0.0,
) -> None:
    """Serve file transfers until the client goes away (host side)."""
    ok_mark, err_mark, info_mark = ok(color), err(color), info(color)
    lim = _TransferLimits(max_size, idle_seconds, max_seconds)
    try:
        conn.settimeout(TRANSFER_TICK)
    except OSError:
        return
    unknown = 0
    try:
        while True:
            if shutdown is not None and shutdown.is_set():
                break
            try:
                ftype, payload = recv_frame(conn)
            except UnknownFrameError:
                unknown += 1
                if unknown >= MAX_UNKNOWN_FRAMES:
                    break
                continue
            except socket.timeout:
                hit = lim.hit()
                if hit is None:
                    continue
                reason = _hit_reason(hit)
                print(
                    f"{info_mark} Transfer von {peer_name} beendet ({reason}).",
                    flush=True,
                )
                _send_terr(conn, reason)
                break
            except (OSError, ValueError):
                break
            lim.touch()
            if ftype != FRAME_TREQ:
                continue
            req = decode_treq(payload)
            if req is None:
                _send_terr(conn, "ungültige Transfer-Anfrage")
                continue
            marks = (ok_mark, err_mark, info_mark)
            if req["op"] == "put":
                _serve_put(conn, root, req, peer_name, marks, shutdown, lim)
            else:
                _serve_get(conn, root, req, peer_name, marks, shutdown, lim)
    except KeyboardInterrupt:
        # once mode: main thread interrupted inside a transfer
        _send_terr(conn, "Host fährt herunter")
        raise


def put_file(
    sock, local: str, remote: str, on_progress=None, on_resume=None,
    fresh: bool = False, deadline: float | None = None,
) -> int:
    """Upload one file; returns bytes sent. Raises TransferError.

    ``on_progress(sent, total)`` is called after every chunk.
    ``on_resume(offset, total)`` is called once when the host continues
    an interrupted upload at ``offset`` instead of starting over.
    ``fresh`` restarts from zero instead of resuming.
    ``deadline`` (monotonic) aborts with a timeout TransferError.
    """
    if os.path.isdir(local):
        raise TransferError(f"ist ein Verzeichnis (nur Dateien): {local}")
    if not os.path.isfile(local):
        raise TransferError(f"Datei nicht lesbar: {local}")
    try:
        size = os.path.getsize(local)
    except OSError:
        raise TransferError(f"Datei nicht lesbar: {local}") from None
    digest = hashlib.sha256()
    try:
        with open(local, "rb") as src:
            while True:
                chunk = src.read(TRANSFER_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        raise TransferError(f"Datei nicht lesbar: {local}") from None
    try:
        treq = encode_treq(
            "put", remote, size, digest.hexdigest(), resume=not fresh
        )
    except ValueError as exc:
        raise TransferError(str(exc)) from None
    if _expired(deadline):
        raise TransferTimeoutError(TIMEOUT_MESSAGE) from None
    sock.settimeout(_phase_timeout(deadline, TRANSFER_ACK_TIMEOUT))
    try:
        _send_frame_or_raise(
            sock, FRAME_TREQ, treq, "Senden fehlgeschlagen"
        )
        ftype, payload = _recv_or_raise(
            sock, "keine Antwort vom Host", deadline
        )
    finally:
        sock.settimeout(None)
    if ftype == FRAME_TERR:
        raise TransferError(_terr_text(payload))
    tack = decode_tack(payload) if ftype == FRAME_TACK else None
    if tack is None or not tack["ok"]:
        raise TransferError(tack["reason"] if tack else "ungültige Antwort")
    offset = _clamp_offset(tack["offset"], size)
    if offset and on_resume is not None:
        on_resume(offset, size)
    sent = offset
    if offset and on_progress is not None:
        on_progress(sent, size)
    try:
        with open(local, "rb") as src:
            if offset:
                src.seek(offset)
            while True:
                if _expired(deadline):
                    raise TransferTimeoutError(TIMEOUT_MESSAGE) from None
                chunk = src.read(TRANSFER_CHUNK_SIZE)
                if not chunk:
                    break
                try:
                    send_frame(sock, FRAME_TDATA, chunk)
                except OSError as exc:
                    raise TransferError(
                        f"Senden fehlgeschlagen: {exc}"
                    ) from exc
                sent += len(chunk)
                if on_progress is not None:
                    on_progress(sent, size)
        commit = json.dumps({"sha256": digest.hexdigest()}).encode("utf-8")
        _send_frame_or_raise(
            sock, FRAME_TDONE, commit, "Senden fehlgeschlagen"
        )
    except TransferError:
        _send_terr(sock, "abgebrochen")
        raise
    sock.settimeout(_phase_timeout(deadline, TRANSFER_ACK_TIMEOUT))
    try:
        ftype, payload = _recv_or_raise(
            sock, "keine Bestätigung vom Host", deadline
        )
    finally:
        sock.settimeout(None)
    if ftype == FRAME_TERR:
        raise TransferError(_terr_text(payload))
    result = _json_dict(payload) if ftype == FRAME_TDONE else None
    if result is None or result.get("ok") is not True:
        reason = result.get("reason") if result else None
        raise TransferError(reason or "ungültige Bestätigung")
    return sent


def _send_result(sock, done: bool, reason: str = "") -> None:
    try:
        send_frame(
            sock, FRAME_TDONE, json.dumps({"ok": done, "reason": reason}).encode()
        )
    except OSError:
        pass


def get_file(
    sock, remote: str, local: str, on_progress=None, on_resume=None,
    fresh: bool = False, deadline: float | None = None,
) -> int:
    """Download one file; returns bytes received. Raises TransferError.

    ``on_progress(sent, total)`` is called after every chunk.
    ``on_resume(offset, total)`` is called once when an interrupted
    download continues at ``offset`` instead of starting over.
    ``fresh`` discards any partial file and restarts from zero.
    ``deadline`` (monotonic) aborts with a timeout TransferError.
    """
    if local.endswith(("/", "\\")) or os.path.isdir(local):
        local = os.path.join(local, os.path.basename(remote))
    tmp = local + PART_SUFFIX
    if fresh:
        _remove_quietly(tmp)
    resume_from = 0
    if os.path.isfile(tmp):
        try:
            resume_from = os.path.getsize(tmp)
        except OSError:
            resume_from = 0
    # Probe writability before any network I/O, mirroring the later open.
    try:
        probe = open(tmp, "ab" if resume_from else "wb")
        probe.close()
    except OSError:
        raise TransferError(
            f"Zieldatei nicht schreibbar: {local}"
        ) from None
    if not resume_from:
        _remove_quietly(tmp)
    try:
        treq = encode_treq(
            "get", remote, resume=not fresh, offset=resume_from
        )
    except ValueError as exc:
        raise TransferError(str(exc)) from None
    if _expired(deadline):
        raise TransferTimeoutError(TIMEOUT_MESSAGE) from None
    out = None
    moved = False
    # Pre-TACK failures keep any pre-existing part for the next attempt.
    keep_part = True
    try:
        sock.settimeout(_phase_timeout(deadline, TRANSFER_ACK_TIMEOUT))
        try:
            _send_frame_or_raise(
                sock, FRAME_TREQ, treq, "Senden fehlgeschlagen"
            )
            ftype, payload = _recv_or_raise(
                sock, "keine Antwort vom Host", deadline
            )
        finally:
            sock.settimeout(None)
        if ftype == FRAME_TERR:
            raise TransferError(_terr_text(payload))
        tack = decode_tack(payload) if ftype == FRAME_TACK else None
        if tack is None or not tack["ok"]:
            raise TransferError(tack["reason"] if tack else "ungültige Antwort")
        size = tack["size"]
        offset = _clamp_offset(tack["offset"], size)
        if offset > resume_from:
            offset = 0
        digest = hashlib.sha256()
        if offset:
            if offset < resume_from:
                try:
                    with open(tmp, "r+b") as handle:
                        handle.truncate(offset)
                except OSError:
                    offset = 0
            if offset:
                digest = _hash_prefix(tmp, offset)
                if digest is None:
                    digest = hashlib.sha256()
                    offset = 0
        if not offset:
            _remove_quietly(tmp)
        elif on_resume is not None:
            on_resume(offset, size)
        try:
            out = open(tmp, "ab" if offset else "wb")
        except OSError:
            reason = f"Zieldatei nicht schreibbar: {local}"
            keep_part = False
            _send_result(sock, False, reason)
            raise TransferError(reason) from None
        received = offset
        if offset and on_progress is not None:
            on_progress(received, size)
        try:
            while True:
                if deadline is not None:
                    if _expired(deadline):
                        raise TransferTimeoutError(TIMEOUT_MESSAGE) from None
                    sock.settimeout(
                        max(0.1, deadline - time.monotonic())
                    )
                try:
                    ftype, payload = recv_frame(sock)
                except socket.timeout:
                    raise TransferTimeoutError(TIMEOUT_MESSAGE) from None
                except UnknownFrameError as exc:
                    raise TransferError(f"Protokollfehler: {exc}") from exc
                except (OSError, ValueError) as exc:
                    raise TransferError(
                        f"Verbindung abgebrochen: {exc}"
                    ) from exc
                if ftype == FRAME_TDATA:
                    try:
                        out.write(payload)
                        # Keep the .ptt-part resume offset crash-honest.
                        out.flush()
                    except OSError:
                        raise TransferError(
                            f"Schreiben fehlgeschlagen: {local}"
                        ) from None
                    digest.update(payload)
                    received += len(payload)
                    if size is not None and received > size:
                        raise TransferError("mehr Daten als angekündigt")
                    if on_progress is not None:
                        on_progress(received, size)
                elif ftype == FRAME_TDONE:
                    break
                elif ftype == FRAME_TERR:
                    raise TransferError(_terr_text(payload))
                # stray frames are ignored
        except TransferError as exc:
            keep_part = not _bad_part(str(exc))
            _send_result(sock, False, str(exc))
            raise
        commit = _json_dict(payload)
        sha = commit.get("sha256") if commit else None
        computed = digest.hexdigest()
        if size is not None and received != size:
            reason = f"unvollständig ({received} von {size} B)"
        elif sha is None or computed != sha:
            reason = "Prüfsumme falsch"
        else:
            out.close()  # Windows: close before replace
            try:
                os.replace(tmp, local)
            except OSError:
                reason = f"Zieldatei nicht schreibbar: {local}"
            else:
                moved = True
                _send_result(sock, True)
                return received
        keep_part = not _bad_part(reason)
        _send_result(sock, False, reason)
        raise TransferError(reason)
    finally:
        if out is not None:
            try:
                out.close()
            except OSError:
                pass
        if not moved and not keep_part:
            _remove_quietly(tmp)
