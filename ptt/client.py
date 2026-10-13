"""PTT client mode: connect to an open tunnel."""
from __future__ import annotations

import contextlib
import getpass
import json
import os
import shlex
import shutil
import signal
import socket
import struct
import sys
import threading
import time

from .auth import normalize_pin
from .cert import peer_fingerprint, tls_client_context
from .discover import DISCOVER_TIMEOUT, discover
from .known_hosts import get_fingerprint, store_fingerprint
from .output import (
    TIMEOUT_EXIT_CODE,
    TIMEOUT_MESSAGE,
    err,
    format_bytes,
    info,
    log_phase,
    ok,
    use_color,
)
from .protocol import (
    ALPN_TRANSFER,
    FRAME_EXIT,
    FRAME_RESIZE,
    FRAME_STDIN,
    FRAME_STDOUT,
    MAX_LINE,
    MAX_UNKNOWN_FRAMES,
    UnknownFrameError,
    enable_keepalive,
    recv_frame,
    recv_line,
    send_frame,
    send_line,
)
from .transfer import (
    TransferError,
    TransferTimeoutError,
    get_file,
    put_file,
    wants_transfer,
)


def _close_quietly(sock) -> None:
    try:
        sock.close()
    except OSError:
        pass


def _terminal_size() -> tuple[int, int]:
    size = shutil.get_terminal_size(fallback=(80, 24))
    return size.columns, size.lines


def _read_loop(sock, out, result: dict, done) -> None:
    """Forward host frames to ``out`` until EXIT (runs in a thread)."""
    try:
        unknown = 0
        while True:
            try:
                ftype, payload = recv_frame(sock)
            except UnknownFrameError:
                unknown += 1
                if unknown >= MAX_UNKNOWN_FRAMES:
                    result["code"] = 1
                    break
                continue
            if ftype == FRAME_STDOUT:
                out.write(payload)
                out.flush()
            elif ftype == FRAME_EXIT and len(payload) == 4:
                result["code"] = struct.unpack("!i", payload)[0]
                break
    except (OSError, ValueError):
        result["code"] = 1
    finally:
        done.set()


def _enable_windows_vt() -> None:
    """Enable ANSI escape processing on the Windows console."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _run_unix(
    sock,
    color: bool = False,
    deadline: float | None = None,
    _out=None,
) -> int:
    import select
    import termios
    import tty

    err_mark, info_mark = err(color), info(color)
    if not sys.stdin.isatty():
        print(f"{err_mark} stdin ist kein Terminal; interaktiver Modus braucht ein TTY.")
        return 2
    try:
        stdin_fd = sys.stdin.fileno()
        old_attrs = termios.tcgetattr(stdin_fd)
    except (OSError, ValueError) as exc:
        print(f"{err_mark} Terminalfehler: {exc}")
        return 1
    old_winch = None
    send_lock = threading.Lock()
    done = threading.Event()
    result = {"code": 0}

    def safe_send(ftype: int, payload: bytes) -> None:
        with send_lock:
            send_frame(sock, ftype, payload)

    stream = _out if _out is not None else sys.stdout.buffer

    def reader() -> None:
        _read_loop(sock, stream, result, done)

    def on_winch(signum, frame) -> None:  # noqa: ARG001
        try:
            cols, rows = _terminal_size()
            safe_send(FRAME_RESIZE, struct.pack("!HH", cols, rows))
        except OSError:
            pass

    thread = threading.Thread(target=reader, daemon=True)
    try:
        tty.setraw(stdin_fd)
        old_winch = signal.signal(signal.SIGWINCH, on_winch)
        cols, rows = _terminal_size()
        safe_send(FRAME_RESIZE, struct.pack("!HH", cols, rows))
        thread.start()
        while not done.is_set():
            if deadline is not None and time.monotonic() > deadline:
                _print_timeout(color)
                result["code"] = TIMEOUT_EXIT_CODE
                _close_quietly(sock)
                break
            ready, _, _ = select.select([stdin_fd], [], [], 0.2)
            if ready:
                data = os.read(stdin_fd, 65536)
                if not data:
                    break
                try:
                    safe_send(FRAME_STDIN, data)
                except OSError:
                    break
    except OSError as exc:
        print(f"\n{err_mark} Terminalfehler: {exc}")
        result["code"] = 1
    finally:
        try:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_attrs)
        except OSError:
            pass
        if old_winch is not None:
            try:
                signal.signal(signal.SIGWINCH, old_winch)
            except OSError:
                pass
        done.set()
    thread.join(timeout=5)
    print(f"\n{info_mark} Verbindung beendet (Exit-Code {result['code']}).")
    return result["code"]


def _run_windows(
    sock,
    color: bool = False,
    deadline: float | None = None,
    _out=None,
) -> int:
    import msvcrt

    _enable_windows_vt()
    err_mark, info_mark = err(color), info(color)
    done = threading.Event()
    result = {"code": 0}
    stream = _out if _out is not None else sys.stdout.buffer

    def reader() -> None:
        _read_loop(sock, stream, result, done)

    # msvcrt extended key codes -> ANSI escape sequences
    special = {
        "H": b"\x1b[A",  # up
        "P": b"\x1b[B",  # down
        "K": b"\x1b[D",  # left
        "M": b"\x1b[C",  # right
        "G": b"\x1b[H",  # home
        "O": b"\x1b[F",  # end
        "R": b"\x1b[2~",  # insert
        "S": b"\x1b[3~",  # delete
        "I": b"\x1b[5~",  # page up
        "Q": b"\x1b[6~",  # page down
    }

    thread = threading.Thread(target=reader, daemon=True)
    last_size = _terminal_size()
    try:
        send_frame(sock, FRAME_RESIZE, struct.pack("!HH", *last_size))
    except OSError:
        print(f"{err_mark} Verbindung abgebrochen.")
        return 1
    thread.start()
    try:
        while not done.is_set():
            if deadline is not None and time.monotonic() > deadline:
                _print_timeout(color)
                result["code"] = TIMEOUT_EXIT_CODE
                _close_quietly(sock)
                break
            current = _terminal_size()
            if current != last_size:
                last_size = current
                try:
                    send_frame(sock, FRAME_RESIZE, struct.pack("!HH", *current))
                except OSError:
                    break
            if msvcrt.kbhit():
                try:
                    ch = msvcrt.getwch()
                except KeyboardInterrupt:
                    data = b"\x03"  # forward Ctrl+C to the remote shell
                else:
                    if ch in ("\x00", "\xe0"):
                        data = special.get(msvcrt.getwch())
                        if data is None:
                            continue
                    elif ch == "\r":
                        data = b"\r"
                    elif ch == "\x08":
                        data = b"\x7f"
                    else:
                        data = ch.encode("utf-8", "replace")
                try:
                    send_frame(sock, FRAME_STDIN, data)
                except OSError:
                    break
            else:
                done.wait(0.05)
    except KeyboardInterrupt:
        pass
    done.set()
    thread.join(timeout=5)
    print(f"\n{info_mark} Verbindung beendet (Exit-Code {result['code']}).")
    return result["code"]


def _short_fingerprint(fingerprint: str) -> str:
    """Abbreviated fingerprint: first + last segment (``SHA256:AB:...:EF``)."""
    parts = (fingerprint or "").split(":")
    if len(parts) >= 4:
        return f"{parts[0]}:{parts[1]}:...:{parts[-1]}"
    return fingerprint or "?"


def _discover_with_progress(
    timeout: float = DISCOVER_TIMEOUT, color: bool = False
) -> list:
    """Discovery with a per-second progress line (quiet when instant)."""
    info_mark = info(color)
    done = threading.Event()

    def ticker() -> None:
        seconds = 0
        while not done.wait(1.0):
            seconds += 1
            print(f"{info_mark} Suche läuft ... ({seconds}s)", flush=True)

    thread = threading.Thread(target=ticker, daemon=True)
    thread.start()
    try:
        return discover(timeout=timeout)
    finally:
        done.set()
        thread.join()


def pick_host(hosts: list, color: bool = False) -> dict | None:
    """Let the user choose one discovered host (single host = auto)."""
    info_mark = info(color)
    if len(hosts) == 1:
        only = hosts[0]
        tag = " (belegt)" if only.get("busy", False) else ""
        print(f"{info_mark} Gefunden: {only['name']} ({only['address']}){tag}")
        return only
    print(f"{info_mark} Gefundene Hosts (per LAN-Suche, netz-vertrauenswürdig):")
    for i, host in enumerate(hosts, 1):
        auth = str(host.get("auth", "?")).upper()
        fp = _short_fingerprint(host.get("fingerprint", ""))
        tag = " (belegt)" if host.get("busy", False) else ""
        print(f"  {i}) {host['name']} ({host['address']}, {auth}, {fp}){tag}")
    for _ in range(3):
        try:
            choice = input("Nummer wählen: ").strip()
        except EOFError:
            print()
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(hosts):
            return hosts[int(choice) - 1]
        print("Ungültige Auswahl.")
    return None


def _prompt_retry() -> str:
    """After an empty search: 'retry', 'ip', or 'abort'."""
    for _ in range(3):
        try:
            choice = input(
                "Erneut suchen (w), IP eingeben (i) oder abbrechen (a)? [w/i/a] "
            ).strip().lower()
        except EOFError:
            print()
            return "abort"
        if choice in ("", "w", "wiederholen"):
            return "retry"
        if choice in ("i", "ip"):
            return "ip"
        if choice in ("a", "abbrechen", "n", "nein"):
            return "abort"
        print("Bitte w, i oder a eingeben.")
    return "abort"


def _prompt_address() -> str | None:
    """Ask for a host address; None when aborted or empty 3 times."""
    for _ in range(3):
        try:
            address = input("Host-Adresse (IP oder Name): ").strip()
        except EOFError:
            print()
            return None
        if address:
            return address
        print("Bitte eine Adresse eingeben.")
    return None


def _search_interactive(
    port: int, color: bool = False
) -> tuple[str, int, str | None, str | None] | None:
    """Discovery with retry/IP/abort (max 3 rounds); None when given up."""
    err_mark, info_mark = err(color), info(color)
    for attempt in range(3):
        print(f"{info_mark} Suche PTT-Hosts im WLAN ...")
        hosts = _discover_with_progress(color=color)
        if hosts:
            chosen = pick_host(hosts, color)
            if chosen is None:
                return None
            return (
                chosen["address"],
                chosen["port"],
                chosen["fingerprint"],
                chosen["auth"],
            )
        print(f"{err_mark} Keine PTT-Hosts gefunden.")
        if attempt >= 2:
            print(
                f"{err_mark} Nächster Schritt: läuft auf dem Ziel `ptt host` "
                "im selben WLAN? Sonst direkt: ptt connect <ip>."
            )
            return None
        action = _prompt_retry()
        if action == "abort":
            return None
        if action == "ip":
            address = _prompt_address()
            if address is None:
                return None
            return (address, port, None, None)
    return None


def _prompt_pin() -> str | None:
    for _ in range(3):
        try:
            raw = input("PIN vom Host-Bildschirm: ")
        except (EOFError, OSError, ValueError):
            return None
        if 6 <= len(normalize_pin(raw)) <= 12:
            return raw
        print("Bitte die PIN vom Host-Bildschirm eingeben (nur Ziffern).")
    return None


def _prompt_hidden(prompt: str) -> str | None:
    try:
        return getpass.getpass(prompt)
    except (EOFError, OSError, ValueError):
        return None


RETRY_BACKOFF_CAP = 30.0  # max seconds between connect retries


def _print_timeout(color: bool) -> None:
    """Report an expired --timeout with the next step."""
    mark = err(color)
    print(f"{mark} {TIMEOUT_MESSAGE}")
    print(
        f"{mark} Nächster Schritt: --timeout erhöhen "
        "oder weglassen (0 = aus)."
    )


def _connect_with_retry(
    hostname: str,
    port: int,
    retry: int,
    retry_delay: float,
    color: bool,
    deadline: float | None = None,
):
    """TCP-connect, retrying ``retry`` times with exponential backoff.

    Returns the connected socket, or None after all attempts failed.
    ``deadline`` (monotonic) aborts early: prints the timeout message
    and raises TimeoutError (the caller maps it to exit code 124).
    """
    info_mark, err_mark = info(color), err(color)
    attempts = max(0, retry) + 1
    delay = max(0.0, retry_delay)
    last_exc: OSError | None = None
    for attempt in range(1, attempts + 1):
        if deadline is not None and time.monotonic() > deadline:
            _print_timeout(color)
            raise TimeoutError from None
        per_attempt = 15.0
        if deadline is not None:
            per_attempt = max(0.1, min(15.0, deadline - time.monotonic()))
        try:
            return socket.create_connection(
                (hostname, port), timeout=per_attempt
            )
        except OSError as exc:
            if (
                isinstance(exc, socket.timeout)
                and deadline is not None
                and time.monotonic() > deadline - 0.5
            ):
                # Per-attempt timeout fired at the deadline, not spuriously.
                _print_timeout(color)
                raise TimeoutError from None
            last_exc = exc
            if attempt < attempts:
                print(
                    f"{info_mark} Versuch {attempt}/{attempts} fehlgeschlagen "
                    f"({exc}), neuer Versuch in {delay:g} s ...",
                    flush=True,
                )
                sleep_for = delay
                if deadline is not None:
                    sleep_for = max(
                        0.0, min(delay, deadline - time.monotonic())
                    )
                time.sleep(sleep_for)
                delay = min(delay * 2, RETRY_BACKOFF_CAP)
    print(f"{err_mark} Keine Verbindung zu {hostname}:{port} ({last_exc})")
    if attempts > 1:
        print(f"{err_mark} {attempts} Versuche fehlgeschlagen.")
    print(
        f"{err_mark} Nächster Schritt: Adresse und WLAN prüfen; "
        f"Firewall für TCP {port} frei?"
    )
    return None


def _as_job_list(value: str | list[str] | None) -> list[str]:
    """Normalize a ``put``/``get`` argument to a spec list."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def run_client(
    hostname: str | None,
    port: int,
    token: str | None,
    color_mode: str = "auto",
    retry: int = 0,
    retry_delay: float = 2.0,
    put: str | list[str] | None = None,
    get: str | list[str] | None = None,
    fresh: bool = False,
    timeout: float = 0,
    quiet: bool = False,
    verbose: bool = False,
    _out=None,
) -> int:
    """Connect to a host and run a session. Returns exit code.

    With ``put`` (``FILE[:NAME]``) uploads files, with ``get``
    (``REMOTE[:LOCAL]``) downloads files instead of a shell; both
    accept one spec or a list. Multiple transfers run sequentially,
    uploads first: exit code is 0 only when all succeed.
    ``fresh`` restarts transfers from zero instead of resuming.
    ``timeout`` caps the whole invocation in seconds (0 disables).
    ``quiet`` routes status output to stderr; stdout carries only
    payload (remote shell output), never status lines.
    ``verbose`` adds timestamped phase lines on stderr.
    """
    if quiet and _out is None:
        # Reenter with stdout captured: prints go to stderr, the
        # session payload keeps the real stdout.
        out = sys.stdout.buffer
        with contextlib.redirect_stdout(sys.stderr):
            return run_client(
                hostname, port, token, color_mode, retry, retry_delay,
                put, get, fresh, timeout, quiet, verbose, _out=out,
            )
    deadline = None
    if timeout and timeout > 0:
        deadline = time.monotonic() + timeout
    jobs = [("put", spec) for spec in _as_job_list(put)]
    jobs += [("get", spec) for spec in _as_job_list(get)]
    if len(jobs) <= 1:
        single_put = jobs[0][1] if jobs and jobs[0][0] == "put" else None
        single_get = jobs[0][1] if jobs and jobs[0][0] == "get" else None
        try:
            return _run_client(
                hostname, port, token, color_mode, retry, retry_delay,
                single_put, single_get, fresh, deadline=deadline,
                _out=_out, verbose=verbose,
            )
        except KeyboardInterrupt:
            print(f"\n{info(use_color(color_mode))} Abgebrochen.")
            return 130
    color = use_color(color_mode)
    ok_mark, err_mark, info_mark = ok(color), err(color), info(color)
    found = None
    if hostname is None:
        found = _search_interactive(port, color)
        if found is None:
            return 1
        hostname = found[0]
    failed = 0
    total = len(jobs)
    for index, (kind, spec) in enumerate(jobs, 1):
        print(f"{info_mark} Transfer {index}/{total}: --{kind} {spec}")
        try:
            if kind == "put":
                rc = _run_client(
                    hostname, port, token, color_mode, retry, retry_delay,
                    spec, None, fresh, deadline=deadline, _found=found,
                    _out=_out, verbose=verbose,
                )
            else:
                rc = _run_client(
                    hostname, port, token, color_mode, retry, retry_delay,
                    None, spec, fresh, deadline=deadline, _found=found,
                    _out=_out, verbose=verbose,
                )
        except KeyboardInterrupt:
            print(f"\n{info_mark} Abgebrochen.")
            return 130
        if rc != 0:
            failed += 1
    if failed:
        print(
            f"{err_mark} {total - failed}/{total} Transfers ok, "
            f"{failed} fehlgeschlagen."
        )
        return 1
    print(f"{ok_mark} {total}/{total} Transfers ok.")
    return 0


def run_exec(
    hostname: str,
    port: int,
    token: str | None,
    color_mode: str = "auto",
    retry: int = 0,
    retry_delay: float = 2.0,
    argv: list[str] | None = None,
    timeout: float = 0,
    quiet: bool = False,
    verbose: bool = False,
    _out=None,
) -> int:
    """Run one remote command. Returns its exit code.

    ``argv`` runs directly on the host, without a shell; remote
    stdout (stderr is merged into it) streams to local stdout.
    ``timeout`` caps the whole invocation in seconds (0 disables).
    ``quiet`` routes status output to stderr; stdout carries only
    the remote command output, never status lines.
    ``verbose`` adds timestamped phase lines on stderr.
    """
    if quiet and _out is None:
        # Reenter with stdout captured: prints go to stderr, the
        # command output keeps the real stdout.
        out = sys.stdout.buffer
        with contextlib.redirect_stdout(sys.stderr):
            return run_exec(
                hostname, port, token, color_mode, retry, retry_delay,
                argv, timeout, quiet, verbose, _out=out,
            )
    deadline = None
    if timeout and timeout > 0:
        deadline = time.monotonic() + timeout
    try:
        return _run_client(
            hostname, port, token, color_mode, retry, retry_delay,
            None, None, False, exec_argv=argv, deadline=deadline,
            _out=_out, verbose=verbose,
        )
    except KeyboardInterrupt:
        print(f"\n{info(use_color(color_mode))} Abgebrochen.")
        return 130


def run_scan(color_mode: str = "auto", as_json: bool = False) -> int:
    """List reachable hosts without connecting. Always returns 0."""
    color = use_color(color_mode)
    info_mark = info(color)
    if not as_json:
        print(f"{info_mark} Suche im WLAN ...", flush=True)
    hosts = discover()
    if as_json:
        print(json.dumps(hosts, ensure_ascii=False, indent=2))
        return 0
    if not hosts:
        print(f"{info_mark} Keine Hosts gefunden.")
        return 0
    print(f"{info_mark} Gefundene Hosts:")
    for i, host in enumerate(hosts, 1):
        auth = str(host.get("auth", "?")).upper()
        fp = _short_fingerprint(host.get("fingerprint", ""))
        tag = " (belegt)" if host.get("busy", False) else ""
        print(f"  {i}) {host['name']} ({host['address']}, {auth}, {fp}){tag}")
    return 0


def _split_put_arg(arg: str) -> tuple[str, str | None]:
    """Split ``FILE[:NAME]``; an existing path wins over the colon rule.

    A single-letter head (``C:\\...``) is a drive path, not ``FILE:NAME``.
    """
    if os.path.exists(arg):
        return arg, None
    head, sep, tail = arg.rpartition(":")
    if sep and tail and not (len(head) == 1 and tail[0] in "/\\"):
        return head, tail
    return arg, None


def _split_get_arg(arg: str) -> tuple[str, str | None]:
    """Split ``REMOTE[:LOCAL]``; drive paths stay whole.

    ``r:C:\\out`` is remote ``r`` with local ``C:\\out``; a lone
    ``C:\\out`` is the remote name (the host rejects it cleanly).
    """
    head, sep, tail = arg.rpartition(":")
    if not sep or not tail:
        return arg, None
    if tail[0] in "/\\":
        if len(head) == 1:
            return arg, None
        if len(head) > 2 and head[-2] == ":":
            return head[:-2], head[-1] + ":" + tail
    return head, tail


class _TransferProgress:
    """TTY progress bar fed via ``on_progress(sent, total)``.

    Silent when stdout is not a TTY. Renders at most every
    ``min_interval`` seconds plus a final line on ``finish()``.
    """

    def __init__(self, min_interval: float = 0.1) -> None:
        self.enabled = sys.stdout.isatty()
        self.min_interval = min_interval
        self.start = time.monotonic()
        # Never shown: -inf, not 0.0 — monotonic() is tiny on fresh
        # boots, and 0.0 would throttle away the first update there.
        self.shown = float("-inf")
        self.state = (0, None)
        try:
            cols = shutil.get_terminal_size().columns
        except OSError:
            cols = 80
        self.width = max(10, min(30, cols - 45))
        self.last_len = 0

    def __call__(self, sent: int, total: int | None) -> None:
        self.state = (sent, total)
        if not self.enabled:
            return
        now = time.monotonic()
        if sent != total and now - self.shown < self.min_interval:
            return
        self.shown = now
        self._render(sent, total)

    def finish(self) -> None:
        """Final line plus newline (no-op when silent)."""
        if not self.enabled:
            return
        sent, total = self.state
        self._render(sent, total)
        print()
        sys.stdout.flush()

    def _render(self, sent: int, total: int | None) -> None:
        if total:
            pct = min(100.0, 100.0 * sent / total)
            filled = min(self.width, int(self.width * sent / total))
            bar = "#" * filled + "-" * (self.width - filled)
            nums = (
                f"{pct:5.1f}% "
                f"{format_bytes(sent)}/{format_bytes(total)}"
            )
        else:
            bar = "-" * self.width
            nums = f"{format_bytes(sent)}"
        elapsed = max(time.monotonic() - self.start, 1e-6)
        rate = f"{format_bytes(int(sent / elapsed))}/s"
        line = f"\r[{bar}] {nums} {rate}"
        line += " " * max(0, self.last_len - len(line))
        self.last_len = len(line)
        print(line, end="", flush=True)


def _run_put(
    sock, local: str, remote: str, color: bool, fresh: bool = False,
    deadline: float | None = None,
) -> int:
    """Upload one file over an authenticated transfer connection."""
    ok_mark, err_mark, info_mark = ok(color), err(color), info(color)
    try:
        if not wants_transfer(sock):
            print(f"{err_mark} Host unterstützt keinen Datei-Transfer.")
            print(
                f"{err_mark} Nächster Schritt: PTT auf dem Host "
                "aktualisieren."
            )
            return 1
        print(f"{info_mark} Sende {local!r} als {remote!r} ...", flush=True)
        progress = _TransferProgress()

        def _resumed(offset: int, total: int | None) -> None:
            print(
                f"{info_mark} Setze abgebrochene Übertragung bei "
                f"{format_bytes(offset)} fort.",
                flush=True,
            )

        try:
            sent = put_file(
                sock, local, remote, on_progress=progress,
                on_resume=_resumed, fresh=fresh, deadline=deadline,
            )
        except TransferTimeoutError:
            progress.finish()
            _print_timeout(color)
            return TIMEOUT_EXIT_CODE
        except TransferError as exc:
            progress.finish()
            print(f"{err_mark} Übertragen fehlgeschlagen: {exc}")
            print(
                f"{err_mark} Nächster Schritt: Fehlermeldung prüfen und "
                "erneut versuchen."
            )
            return 1
        progress.finish()
        print(f"{ok_mark} Übertragen: {format_bytes(sent)}.", flush=True)
        return 0
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _run_get(
    sock, remote: str, local: str, color: bool, fresh: bool = False,
    deadline: float | None = None,
) -> int:
    """Download one file over an authenticated transfer connection."""
    ok_mark, err_mark, info_mark = ok(color), err(color), info(color)
    try:
        if not wants_transfer(sock):
            print(f"{err_mark} Host unterstützt keinen Datei-Transfer.")
            print(
                f"{err_mark} Nächster Schritt: PTT auf dem Host "
                "aktualisieren."
            )
            return 1
        print(f"{info_mark} Empfange {remote!r} nach {local!r} ...", flush=True)
        progress = _TransferProgress()

        def _resumed(offset: int, total: int | None) -> None:
            print(
                f"{info_mark} Setze abgebrochenen Download bei "
                f"{format_bytes(offset)} fort.",
                flush=True,
            )

        try:
            received = get_file(
                sock, remote, local, on_progress=progress,
                on_resume=_resumed, fresh=fresh, deadline=deadline,
            )
        except TransferTimeoutError:
            progress.finish()
            _print_timeout(color)
            return TIMEOUT_EXIT_CODE
        except TransferError as exc:
            progress.finish()
            print(f"{err_mark} Übertragen fehlgeschlagen: {exc}")
            print(
                f"{err_mark} Nächster Schritt: Fehlermeldung prüfen und "
                "erneut versuchen."
            )
            return 1
        progress.finish()
        print(f"{ok_mark} Übertragen: {format_bytes(received)}.", flush=True)
        return 0
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _forward_exec_stdin(sock) -> None:
    """Pipe local stdin to the remote command, then send the EOF marker.

    Runs in a daemon thread; ends at local EOF or when the socket dies.
    """
    inp = getattr(sys.stdin, "buffer", None)
    if inp is not None:
        try:
            while True:
                chunk = inp.read(65536)
                if not chunk:
                    break
                send_frame(sock, FRAME_STDIN, chunk)
        except (OSError, ValueError):
            return
    try:
        send_frame(sock, FRAME_STDIN, b"")
    except (OSError, ValueError):
        pass


def _run_exec_session(
    sock, color: bool, deadline: float | None = None, _out=None
) -> int:
    """Run one remote command over an authenticated connection.

    No raw mode, no local terminal needed: remote stdout streams to
    local stdout, the EXIT code becomes the return value.
    """
    err_mark = err(color)
    out = _out if _out is not None else sys.stdout.buffer
    sender = threading.Thread(
        target=_forward_exec_stdin, args=(sock,), daemon=True
    )
    sender.start()
    code = 1
    finished = False
    try:
        unknown = 0
        while True:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _print_timeout(color)
                    return TIMEOUT_EXIT_CODE
                sock.settimeout(remaining)
            try:
                ftype, payload = recv_frame(sock)
            except socket.timeout:
                _print_timeout(color)
                return TIMEOUT_EXIT_CODE
            except UnknownFrameError:
                unknown += 1
                if unknown >= MAX_UNKNOWN_FRAMES:
                    break
                continue
            if ftype == FRAME_STDOUT:
                try:
                    out.write(payload)
                    out.flush()
                except OSError:
                    return 1  # local stdout gone (e.g. piped to head)
            elif ftype == FRAME_EXIT and len(payload) == 4:
                code = struct.unpack("!i", payload)[0]
                finished = True
                break
    except (OSError, ValueError):
        code = 1
    finally:
        _close_quietly(sock)
    if not finished:
        print(f"{err_mark} Verbindung abgebrochen.")
        print(
            f"{err_mark} Nächster Schritt: Host-Erreichbarkeit prüfen "
            "und erneut versuchen."
        )
    return code


def _run_client(
    hostname: str | None,
    port: int,
    token: str | None,
    color_mode: str,
    retry: int = 0,
    retry_delay: float = 2.0,
    put: str | None = None,
    get: str | None = None,
    fresh: bool = False,
    exec_argv: list[str] | None = None,
    deadline: float | None = None,
    _found=None,
    _out=None,
    verbose: bool = False,
) -> int:
    color = use_color(color_mode)
    phase_start = time.monotonic()
    ok_mark, err_mark, info_mark = ok(color), err(color), info(color)
    local_path, remote_name = "", ""
    if put is not None:
        local_path, remote_name = _split_put_arg(put)
        remote_name = remote_name or os.path.basename(local_path)
        if os.path.isdir(local_path):
            print(f"{err_mark} Ist ein Verzeichnis (nur Dateien): {local_path}")
            return 1
        if not os.path.isfile(local_path):
            print(f"{err_mark} Datei nicht gefunden: {local_path}")
            return 1
    get_remote, get_local = "", ""
    if get is not None:
        get_remote, get_local = _split_get_arg(get)
        if not get_local:
            base = os.path.basename(get_remote)
            if base in ("", ".", ".."):
                print(
                    f"{err_mark} Ungültiger Remote-Name: {get_remote!r} "
                    "(Ziel mit NAME:LOKAL angeben)."
                )
                return 1
            get_local = base
    if exec_argv is not None and not exec_argv:
        print(f"{err_mark} exec braucht einen Befehl.")
        return 2
    expected_fp: str | None = None
    auth_kind: str | None = None
    if _found is not None:
        hostname, port, expected_fp, auth_kind = _found
    elif hostname is None:
        found = _search_interactive(port, color)
        if found is None:
            return 1
        hostname, port, expected_fp, auth_kind = found
    print(f"{info_mark} Verbinde mit {hostname}:{port} ...")
    try:
        raw = _connect_with_retry(
            hostname, port, retry, retry_delay, color, deadline
        )
    except TimeoutError:
        return TIMEOUT_EXIT_CODE
    if raw is None:
        return 1
    log_phase(verbose, phase_start, f"TCP verbunden ({hostname}:{port})")
    enable_keepalive(raw)
    transfer_mode = put is not None or get is not None
    context = tls_client_context([ALPN_TRANSFER] if transfer_mode else None)
    if deadline is not None:
        raw.settimeout(max(0.1, deadline - time.monotonic()))
    try:
        sock = context.wrap_socket(raw, server_hostname=hostname)
    except socket.timeout:
        _print_timeout(color)
        raw.close()
        return TIMEOUT_EXIT_CODE
    except OSError as exc:
        print(f"{err_mark} TLS-Fehler: {exc}")
        print(
            f"{err_mark} Nächster Schritt: PTT auf beiden Seiten aktualisieren "
            "und erneut versuchen."
        )
        raw.close()
        return 1
    # wrap_socket detaches raw and copies its timeout: restore on sock.
    sock.settimeout(None)
    log_phase(verbose, phase_start, f"TLS-Handshake ok ({sock.version()})")
    peer_fp = peer_fingerprint(sock)
    print(f"{info_mark} Host-Fingerabdruck: {peer_fp}")
    if expected_fp is not None:
        if peer_fp != expected_fp:
            print(
                f"{err_mark} Fingerabdruck stimmt NICHT mit der Ankündigung überein - "
                "Abbruch (Angriff möglich)."
            )
            print(
                f"{err_mark} Nächster Schritt: richtigen Host gewählt und Netz "
                "prüfen; im Zweifel abbrechen."
            )
            sock.close()
            return 1
        print(f"{ok_mark} Fingerabdruck stimmt mit der Ankündigung überein.")
        fp_how = "Ankündigung ok"
    else:
        known = get_fingerprint(hostname, port)
        if known is None:
            try:
                store_fingerprint(hostname, port, peer_fp)
            except OSError:
                print(
                    f"{err_mark} Fingerabdruck konnte nicht gespeichert "
                    "werden; ohne TOFU-Schutz fortgefahren."
                )
            else:
                print(
                    f"{info_mark} Fingerabdruck für künftige Verbindungen "
                    "gespeichert."
                )
            print(
                f"{info_mark} Bei Bedarf mit dem Fingerabdruck auf dem Host "
                "vergleichen."
            )
            fp_how = "neu"
        elif known != peer_fp:
            print(f"{err_mark} Fingerabdruck hat sich GEÄNDERT - Abbruch (Angriff möglich).")
            print(
                f"{err_mark} Wenn der Host neu aufgesetzt wurde: Eintrag aus "
                "~/.ptt/known_hosts entfernen und erneut verbinden."
            )
            sock.close()
            return 1
        else:
            print(f"{ok_mark} Fingerabdruck stimmt mit dem gespeicherten überein.")
            fp_how = "gespeichert ok"
    log_phase(verbose, phase_start, f"Host geprüft ({fp_how})")
    secret: str | None = token
    if secret is None:
        try:
            if auth_kind == "pin":
                secret = _prompt_pin()
            elif auth_kind == "token":
                secret = _prompt_hidden("Token: ")
            else:
                secret = _prompt_hidden("PIN oder Token: ")
        except KeyboardInterrupt:
            _close_quietly(sock)
            raise
        if secret is None:
            print()
            sock.close()
            return 2
    try:
        line = secret.strip()
        if exec_argv is not None:
            line = "EXEC " + line + " " + shlex.join(exec_argv)
            if len(line.encode("utf-8")) > MAX_LINE:
                print(
                    f"{err_mark} Befehl zu lang für exec "
                    f"(max. {MAX_LINE} Zeichen)."
                )
                sock.close()
                return 2
        if deadline is not None:
            sock.settimeout(max(0.1, deadline - time.monotonic()))
        send_line(sock, line)
        answer = recv_line(sock).strip()
    except socket.timeout:
        _print_timeout(color)
        sock.close()
        return TIMEOUT_EXIT_CODE
    except KeyboardInterrupt:
        _close_quietly(sock)
        raise
    except OSError as exc:
        print(f"{err_mark} Auth fehlgeschlagen ({exc})")
        print(f"{err_mark} Nächster Schritt: Verbindung prüfen und erneut versuchen.")
        sock.close()
        return 1
    sock.settimeout(None)
    if answer == "BUSY":
        print(f"{err_mark} Host ist ausgelastet (max. Sitzungszahl erreicht).")
        print(f"{err_mark} Nächster Schritt: später erneut versuchen.")
        sock.close()
        return 1
    if answer != "OK":
        print(f"{err_mark} Zugriff verweigert (falsches Token?).")
        print(
            f"{err_mark} Nächster Schritt: Befehl wiederholen und PIN/Token "
            "vom Host-Bildschirm prüfen."
        )
        sock.close()
        return 1
    log_phase(verbose, phase_start, "Auth ok")
    if exec_argv is not None:
        log_phase(verbose, phase_start, "Modus: exec")
        return _run_exec_session(sock, color, deadline, _out)
    if put is not None:
        log_phase(verbose, phase_start, "Modus: put")
        return _run_put(sock, local_path, remote_name, color, fresh, deadline)
    if get is not None:
        log_phase(verbose, phase_start, "Modus: get")
        return _run_get(sock, get_remote, get_local, color, fresh, deadline)
    log_phase(verbose, phase_start, "Modus: shell")
    print(f"{ok_mark} Verbunden. Beenden mit `exit` in der Remote-Shell.", flush=True)
    try:
        if os.name == "nt":
            return _run_windows(sock, color, deadline, _out)
        return _run_unix(sock, color, deadline, _out)
    finally:
        try:
            sock.close()
        except OSError:
            pass
