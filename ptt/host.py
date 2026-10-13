"""PTT host mode: open a tunnel and serve a terminal session."""
from __future__ import annotations

import hmac
import os
import random
import select
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import NamedTuple

from .auth import format_pin, generate_pin, normalize_pin
from .cert import cert_fingerprint, ensure_cert, tls_server_context
from .discover import DISCOVERY_PORT, start_responder
from .output import (
    ANSI,
    err,
    format_bytes,
    format_duration,
    info,
    log_phase,
    ok,
    paint,
)
from .transfer import cleanup_stale_parts, serve_transfer, wants_transfer
from .output import use_color  # noqa: F401 (re-export, deprecated: use ptt.output)
from .protocol import (
    FRAME_RESIZE,
    FRAME_STDIN,
    FRAME_STDOUT,
    MAX_UNKNOWN_FRAMES,
    UnknownFrameError,
    enable_keepalive,
    recv_frame,
    recv_line,
    send_exit,
    send_frame,
    send_line,
)

try:
    import fcntl
    import pty
    import termios

    HAVE_PTY = True
except ImportError:  # Windows has no pty/fcntl/termios
    HAVE_PTY = False

DEFAULT_PORT = 8022
AUTH_TIMEOUT = 30.0
PIN_MAX_FAILURES = 5
PIN_WINDOW_SECONDS = 300
BACKOFF_MAX_SECONDS = 30.0
READER_JOIN_TIMEOUT = 5.0
SHUTDOWN_JOIN_TIMEOUT = 15.0
IDLE_TIMEOUT_EXIT_CODE = 124  # like GNU timeout(1)


def _exit_code_from_returncode(returncode: int) -> int:
    """Map a process returncode to a session EXIT code (ssh convention).

    Negative codes (died by signal N) become 128+N; passing them
    through would surface a wrapped value on the client (247 for
    SIGKILL instead of 137).
    """
    if returncode < 0:
        return 128 + (-returncode)
    return returncode


def _start_session_reader(target) -> threading.Thread:
    """Start the daemon socket-reader thread of one session.

    Pair with ``reader.join(timeout=READER_JOIN_TIMEOUT)`` at teardown.
    """
    reader = threading.Thread(target=target, daemon=True)
    reader.start()
    return reader

def _row(label: str, value: str) -> str:
    return f"{label + ':':<15} {value}"


def format_banner(
    port: int,
    ips: list,
    name: str,
    secret: str,
    kind: str,
    fingerprint: str,
    discover_enabled: bool,
    shell: str,
    *,
    color: bool,
    unicode_box: bool,
) -> str:
    """Startup banner: connection info inside a (colored) frame."""
    rows = [
        ("PTT Host - Tunnel offen", "title"),
        ("", None),
        (_row("Name", name), None),
    ]
    if kind == "pin":
        rows.append((_row("PIN", format_pin(secret)), "secret"))
    else:
        rows.append((_row("Token", secret), "secret"))
    rows.append((_row("Shell", shell), None))
    rows.append(("", None))
    if discover_enabled:
        what = "PIN" if kind == "pin" else "Token"
        rows.append((_row("Client", f"ptt connect  ->  '{name}' wählen  ->  {what} eingeben"), None))
    else:
        rows.append((_row("Suche", "deaktiviert (direkt verbinden, s. unten)"), None))
    direct, extra = list(ips), 0
    if len(direct) > 3:
        extra = len(direct) - 1
        direct = direct[:1]
    for ip in direct:
        rows.append((_row("Direkt", f"ptt connect {ip} --port {port}"), None))
    if extra:
        rows.append((_row("Direkt", f"+{extra} weitere Adressen"), None))
    rows.extend(
        [
            (_row("Fingerabdruck", fingerprint), None),
            ("", None),
            ("Beenden: Strg+C", None),
        ]
    )
    width = max(len(text) for text, _ in rows)
    if unicode_box:
        tl, tr, bl, br, h, v = ("╭", "╮", "╰", "╯", "─", "│")
    else:
        tl, tr, bl, br, h, v = ("+", "+", "+", "+", "-", "|")
    cyan = ANSI["cyan"] if color else ""
    reset = ANSI["reset"] if color else ""
    lines = [f"{cyan}{tl}{h * (width + 2)}{tr}{reset}"]
    for text, tag in rows:
        if tag == "title":
            content = paint(color, ANSI["bold"], text.ljust(width))
        elif tag == "secret":
            content = paint(color, ANSI["bright_green"], text.ljust(width))
        else:
            content = text.ljust(width)
        lines.append(f"{cyan}{v}{reset} {content} {cyan}{v}{reset}")
    lines.append(f"{cyan}{bl}{h * (width + 2)}{br}{reset}")
    return "\n".join(lines)


def print_banner(
    port: int,
    ips: list,
    name: str,
    secret: str,
    kind: str,
    fingerprint: str,
    discover_enabled: bool,
    shell: str,
    color_mode: str,
) -> bool:
    """Print the framed banner. Returns whether colors were used."""
    color = use_color(color_mode)
    encoding = (sys.stdout.encoding or "").lower()
    banner = format_banner(
        port,
        ips,
        name,
        secret,
        kind,
        fingerprint,
        discover_enabled,
        shell,
        color=color,
        unicode_box="utf" in encoding,
    )
    print(banner, flush=True)
    return color


def _failures_for(failures: dict[str, list[float]], ip: str) -> list[float]:
    """Pruned failure timestamps for ``ip`` (brute-force brake state)."""
    stamps = failures.setdefault(ip, [])
    cutoff = time.time() - PIN_WINDOW_SECONDS
    while stamps and stamps[0] < cutoff:
        stamps.pop(0)
    return stamps


def _locked_out(failures: dict[str, list[float]], ip: str) -> bool:
    """True after too many wrong secrets from ``ip`` (per-IP brake)."""
    return len(_failures_for(failures, ip)) >= PIN_MAX_FAILURES


def _lockout_wait(failures: dict[str, list[float]], ip: str) -> float:
    """Seconds until ``ip`` may retry (0 when not locked out)."""
    stamps = _failures_for(failures, ip)
    if len(stamps) < PIN_MAX_FAILURES:
        return 0.0
    return max(0.0, stamps[0] + PIN_WINDOW_SECONDS - time.time())


def _backoff_delay(failures: int) -> float:
    """Exponential backoff with jitter: 1s, 2s, 4s, ... capped at 30s."""
    base = min(2.0 ** max(0, failures - 1), BACKOFF_MAX_SECONDS)
    return base + random.uniform(0, 0.5)


def default_shell() -> str:
    if os.name == "nt":
        return os.environ.get("COMSPEC", "powershell.exe")
    return os.environ.get("SHELL", "/bin/bash")


def _validate_shell(shell: str) -> None:
    """Raise ValueError when ``shell`` cannot be executed."""
    if os.path.dirname(shell):
        if not (os.path.isfile(shell) and os.access(shell, os.X_OK)):
            raise ValueError(f"--shell nicht ausführbar: {shell}")
    elif shutil.which(shell) is None:
        raise ValueError(f"--shell nicht gefunden: {shell}")


def local_ips() -> list[str]:
    """Best-effort LAN addresses of this machine (for the connect hint)."""
    ips: list[str] = []
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))  # no traffic sent, local addr only
            ips.append(probe.getsockname()[0])
        finally:
            probe.close()
    except OSError:
        pass
    try:
        for addr in socket.gethostbyname_ex(socket.gethostname())[2]:
            if addr not in ips:
                ips.append(addr)
    except OSError:
        pass
    return ips or ["127.0.0.1"]


def _set_winsize(fd: int, cols: int, rows: int) -> None:
    if not HAVE_PTY:
        return
    cols = max(1, min(cols, 1000))
    rows = max(1, min(rows, 1000))
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


class SessionResult(NamedTuple):
    """How a session ended: reason plus traffic stats."""

    reason: str  # "ended", "idle" or "expired"
    bytes_in: int  # client -> shell
    bytes_out: int  # shell -> client
    seconds: float  # session duration


def _serve_pty(
    conn,
    shell: str,
    idle_seconds: float = 0.0,
    max_seconds: float = 0.0,
    shutdown: threading.Event | None = None,
) -> SessionResult:
    """Serve one session with a real pseudo-terminal (Unix)."""
    master, slave = pty.openpty()
    _set_winsize(slave, 80, 24)
    try:
        proc = subprocess.Popen(
            [shell],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            preexec_fn=os.setsid,
            close_fds=True,
        )
    except OSError:
        os.close(slave)
        os.close(master)
        raise
    os.close(slave)
    stop = threading.Event()
    started = time.monotonic()
    last_active = [started]
    reason = "ended"
    bytes_in = [0]  # written by the reader thread
    bytes_out = 0

    def sock_to_pty() -> None:
        try:
            unknown = 0
            while not stop.is_set():
                try:
                    ftype, payload = recv_frame(conn)
                except UnknownFrameError:
                    unknown += 1
                    if unknown >= MAX_UNKNOWN_FRAMES:
                        break
                    continue
                last_active[0] = time.monotonic()
                if ftype == FRAME_STDIN:
                    bytes_in[0] += len(payload)
                    os.write(master, payload)
                elif ftype == FRAME_RESIZE and len(payload) == 4:
                    cols, rows = struct.unpack("!HH", payload)
                    _set_winsize(master, cols, rows)
        except OSError:
            pass
        finally:
            stop.set()

    reader = _start_session_reader(sock_to_pty)
    exit_code = 0
    try:
        while True:
            if shutdown is not None and shutdown.is_set():
                try:
                    proc.terminate()
                except OSError:
                    pass
                break
            now = time.monotonic()
            if max_seconds > 0 and now - started > max_seconds:
                reason = "expired"
            elif idle_seconds > 0 and now - last_active[0] > idle_seconds:
                reason = "idle"
            if reason != "ended":
                stop.set()
                try:
                    proc.terminate()
                except OSError:
                    pass
                break
            exited = proc.poll()
            try:
                ready, _, _ = select.select([master], [], [], 0.2)
            except (OSError, ValueError):
                break
            if ready:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    break  # EIO: shell exited
                if not data:
                    break
                last_active[0] = time.monotonic()
                bytes_out += len(data)
                try:
                    send_frame(conn, FRAME_STDOUT, data)
                except OSError:
                    break
            if exited is not None:
                try:  # drain remaining output
                    while True:
                        ready, _, _ = select.select([master], [], [], 0)
                        if not ready:
                            break
                        data = os.read(master, 65536)
                        if not data:
                            break
                        bytes_out += len(data)
                        send_frame(conn, FRAME_STDOUT, data)
                except OSError:
                    pass
                exit_code = _exit_code_from_returncode(exited)
                break
            if stop.is_set():  # client gone: stop the shell
                try:
                    proc.terminate()
                except OSError:
                    pass
                break
    finally:
        stop.set()
        if reason != "ended":
            exit_code = IDLE_TIMEOUT_EXIT_CODE
        try:
            send_exit(conn, exit_code)
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
        os.close(master)
        reader.join(timeout=READER_JOIN_TIMEOUT)
    return SessionResult(reason, bytes_in[0], bytes_out, time.monotonic() - started)


def _serve_pipes(
    conn,
    command: str | list[str],
    idle_seconds: float = 0.0,
    max_seconds: float = 0.0,
    shutdown: threading.Event | None = None,
) -> SessionResult:
    """Serve one session with plain pipes (fallback without PTY, e.g. Windows).

    Works for basic commands; fullscreen programs (vim, htop) need a PTY
    and will not work in this mode. ``command`` is the shell path or an
    explicit argv list (exec mode); stderr is merged into stdout.
    """
    argv = [command] if isinstance(command, str) else list(command)
    if not argv:
        raise ValueError("leeres argv")
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
    except (OSError, ValueError):
        # Unknown program (or broken argv): shell-style 127, no traceback.
        try:
            send_exit(conn, 127)
        except OSError:
            pass
        return SessionResult("ended", 0, 0, 0.0)
    stop = threading.Event()
    started = time.monotonic()
    last_active = [started]
    reason = ["ended"]
    bytes_in = [0]  # written by the reader thread
    bytes_out = 0

    def sock_to_proc() -> None:
        stdin = proc.stdin
        try:
            unknown = 0
            while not stop.is_set():
                try:
                    ftype, payload = recv_frame(conn)
                except UnknownFrameError:
                    unknown += 1
                    if unknown >= MAX_UNKNOWN_FRAMES:
                        break
                    continue
                last_active[0] = time.monotonic()
                if ftype == FRAME_STDIN and stdin is not None:
                    if not payload:
                        # EOF marker (exec stdin piping).
                        try:
                            stdin.close()
                        except OSError:
                            pass
                        stdin = None
                    else:
                        bytes_in[0] += len(payload)
                        stdin.write(payload)
                        stdin.flush()
        except (OSError, ValueError):
            pass
        finally:
            stop.set()
            try:  # session over when the socket ends: free the shell
                proc.terminate()
            except OSError:
                pass

    def session_watchdog() -> None:
        while not stop.wait(1.0):
            if shutdown is not None and shutdown.is_set():
                stop.set()
                try:
                    proc.terminate()
                except OSError:
                    pass
                return
            now = time.monotonic()
            if max_seconds > 0 and now - started > max_seconds:
                reason[0] = "expired"
            elif idle_seconds > 0 and now - last_active[0] > idle_seconds:
                reason[0] = "idle"
            else:
                continue
            stop.set()
            try:
                proc.terminate()
            except OSError:
                pass
            return

    reader = _start_session_reader(sock_to_proc)
    if idle_seconds > 0 or max_seconds > 0 or shutdown is not None:
        watcher = threading.Thread(target=session_watchdog, daemon=True)
        watcher.start()
    try:
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        while not stop.is_set():
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            last_active[0] = time.monotonic()
            bytes_out += len(data)
            try:
                send_frame(conn, FRAME_STDOUT, data)
            except OSError:
                break
    finally:
        stop.set()
        if proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
        exit_code = proc.poll()
        if reason[0] != "ended" or exit_code is None:
            exit_code = IDLE_TIMEOUT_EXIT_CODE if reason[0] != "ended" else 0
        else:
            exit_code = _exit_code_from_returncode(exit_code)
        try:
            send_exit(conn, exit_code)
        except OSError:
            pass
        if proc.poll() is None:  # reap shells that ignore SIGTERM
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except OSError:
                    pass
        reader.join(timeout=READER_JOIN_TIMEOUT)
        for pipe in (proc.stdin, proc.stdout):
            try:
                if pipe is not None:
                    pipe.close()
            except OSError:
                pass
    return SessionResult(
        reason[0], bytes_in[0], bytes_out, time.monotonic() - started
    )


def _serve_exec(
    conn,
    argv: list[str],
    idle_seconds: float = 0.0,
    max_seconds: float = 0.0,
    shutdown: threading.Event | None = None,
) -> SessionResult:
    """Run one non-interactive command; argv runs directly, no shell."""
    return _serve_pipes(conn, argv, idle_seconds, max_seconds, shutdown)


def _exec_args(rest: str, kind: str, secret: str) -> list[str] | None:
    """Argv from an EXEC hello tail, or None when not an exec request."""
    if kind == "pin":
        candidate, sep, argtext = rest.partition(" ")
        if not sep or not hmac.compare_digest(
            normalize_pin(candidate), secret
        ):
            return None
    else:
        if rest == secret or not rest.startswith(secret + " "):
            return None
        argtext = rest[len(secret) + 1 :]
    if not argtext.strip():
        return None
    try:
        argv = shlex.split(argtext, posix=(os.name != "nt"))
    except ValueError:
        return None
    return argv or None


def _parse_hello(given: str, kind: str, secret: str) -> tuple[bool, list[str] | None]:
    """Check a hello line; returns (authenticated, exec-argv-or-None).

    ``EXEC <secret> <argv …>`` selects exec mode, a bare ``<secret>``
    line keeps the legacy shell/transfer session. A failed EXEC parse
    falls back to the plain-secret comparison so secrets starting
    with ``EXEC `` keep working as before.
    """
    if given.startswith("EXEC "):
        argv = _exec_args(given[5:], kind, secret)
        if argv is not None:
            return True, argv
    candidate = normalize_pin(given) if kind == "pin" else given
    return hmac.compare_digest(candidate, secret), None


def _handle_connection(
    conn,
    shell: str,
    secret: str,
    kind: str,
    color: bool,
    failures: dict[str, list[float]],
    idle_timeout: float = 0.0,
    max_session: float = 0.0,
    shutdown: threading.Event | None = None,
    transfer_dir: str | None = None,
    max_transfer_size: int = 0,
    verbose: bool = False,
) -> bool:
    """Serve one connection. Returns True if the client authenticated.

    ``idle_timeout``/``max_session`` are minutes (0 disables); on timeout
    the client receives exit code 124. When ``shutdown`` is set, the
    session ends early with a clean EXIT frame.
    """
    ok_mark, err_mark, info_mark = ok(color), err(color), info(color)
    phase_start = time.monotonic()
    what = "Falsche PIN" if kind == "pin" else "Falsches Token"
    try:
        peer = conn.getpeername()
    except OSError:
        peer = None
    if isinstance(peer, tuple) and len(peer) >= 2:
        peer_ip, peer_name = peer[0], f"{peer[0]}:{peer[1]}"
    else:
        peer_ip, peer_name = "?", "?"
    print(f"{ok_mark} Verbindung von {peer_name}", flush=True)
    conn.settimeout(AUTH_TIMEOUT)
    try:
        try:
            given = recv_line(conn).strip()
        except OSError:
            print(f"{err_mark} Auth-Timeout, Verbindung geschlossen.", flush=True)
            return False
        log_phase(verbose, phase_start, "Hello empfangen")
        authed, argv = _parse_hello(given, kind, secret)
        if not authed:
            stamps = _failures_for(failures, peer_ip)
            stamps.append(time.time())
            # Slow the attacker down. This briefly blocks this session
            # thread; the accept loop keeps serving other clients.
            time.sleep(_backoff_delay(len(stamps)))
            print(f"{err_mark} {what} von {peer_name}, abgewiesen.", flush=True)
            log_phase(verbose, phase_start, "Auth abgelehnt")
            try:
                send_line(conn, "DENIED")
            except OSError:
                pass
            return False
        failures.pop(peer_ip, None)  # success forgives past typos
        log_phase(verbose, phase_start, f"Auth ok ({kind})")
        send_line(conn, "OK")
        conn.settimeout(None)
        idle_seconds = max(0.0, idle_timeout) * 60
        max_seconds = max(0.0, max_session) * 60
        if argv is not None:
            # Log only the program, never full argv (may hold secrets).
            print(
                f"{ok_mark} Auth OK ({peer_name}), exec startet: {argv[0]}",
                flush=True,
            )
            log_phase(verbose, phase_start, "Modus: exec")
            result = _serve_exec(
                conn, argv, idle_seconds, max_seconds, shutdown
            )
        elif wants_transfer(conn):
            print(
                f"{ok_mark} Auth OK ({peer_name}), Transfer startet.",
                flush=True,
            )
            log_phase(verbose, phase_start, "Modus: transfer")
            serve_transfer(
                conn, transfer_dir or os.getcwd(), peer_name, color,
                shutdown, max_transfer_size, idle_seconds, max_seconds,
            )
            log_phase(verbose, phase_start, "Transfer beendet")
            return True
        else:
            print(
                f"{ok_mark} Auth OK ({peer_name}), Shell startet: {shell}",
                flush=True,
            )
            log_phase(verbose, phase_start, "Modus: shell")
            if HAVE_PTY:
                result = _serve_pty(
                    conn, shell, idle_seconds, max_seconds, shutdown
                )
            else:
                result = _serve_pipes(
                    conn, shell, idle_seconds, max_seconds, shutdown
                )
        stats = (
            f"Dauer {format_duration(result.seconds)}, "
            f"{format_bytes(result.bytes_in)} up / "
            f"{format_bytes(result.bytes_out)} down"
        )
        if result.reason == "expired":
            print(
                f"{info_mark} Sitzung mit {peer_name} beendet "
                f"(maximale Sitzungsdauer erreicht; {stats}).",
                flush=True,
            )
        elif result.reason == "idle":
            print(
                f"{info_mark} Sitzung mit {peer_name} beendet "
                f"(Inaktivität; {stats}).",
                flush=True,
            )
        else:
            print(
                f"{info_mark} Sitzung mit {peer_name} beendet ({stats}).",
                flush=True,
            )
        log_phase(
            verbose, phase_start,
            f"Sitzung beendet ({result.reason}, {result.seconds:0.1f}s)",
        )
        return True
    except OSError as exc:
        print(f"{err_mark} Verbindungsfehler ({peer_name}): {exc}", flush=True)
        return False


def _on_sigterm(signum, frame) -> None:
    """Shut down cleanly on SIGTERM via the KeyboardInterrupt path."""
    raise KeyboardInterrupt


def _make_sigint_handler():
    """Return a SIGINT handler: first Ctrl+C cleans up, second aborts."""
    interrupted = False

    def _on_sigint(signum, frame) -> None:
        nonlocal interrupted
        if interrupted:
            os._exit(130)  # second Ctrl+C during cleanup: abort now
            return  # unreachable (os._exit never returns); guards mocks
        interrupted = True
        raise KeyboardInterrupt

    return _on_sigint


def _install_shutdown_handlers():
    """Install SIGTERM/SIGINT handlers; return previous ones (or None).

    Only the main thread may set signal handlers; other threads (e.g.
    in tests) keep the defaults and get None.
    """
    if threading.current_thread() is not threading.main_thread():
        return None
    try:
        old_term = signal.signal(signal.SIGTERM, _on_sigterm)
        old_int = signal.signal(signal.SIGINT, _make_sigint_handler())
    except (OSError, ValueError, RuntimeError):
        return None
    return (old_term, old_int)


def _restore_shutdown_handlers(old) -> None:
    """Restore handlers saved by :func:`_install_shutdown_handlers`."""
    if old is None:
        return
    old_term, old_int = old
    for signum, handler in ((signal.SIGTERM, old_term), (signal.SIGINT, old_int)):
        try:
            signal.signal(signum, handler)
        except (OSError, ValueError, RuntimeError):
            pass


def run_host(
    bind: str,
    port: int,
    shell: str,
    token: str | None,
    cert_dir: str,
    once: bool = False,
    color_mode: str = "auto",
    name: str | None = None,
    pin: str | None = None,
    discover: bool = True,
    discovery_port: int = DISCOVERY_PORT,
    idle_timeout: float = 0.0,
    max_session: float = 0.0,
    max_sessions: int = 1,
    transfer_dir: str | None = None,
    max_transfer_size: int = 0,
    verbose: bool = False,
) -> None:
    """Open the tunnel and serve sessions until Ctrl+C (or one if ``once``).

    ``max_sessions`` caps concurrent sessions (0 = unlimited); waiting
    clients are rejected with BUSY. ``once`` always serves a single
    session inline and ignores ``max_sessions``. ``transfer_dir`` is the
    target root for file uploads (default: working directory);
    ``max_transfer_size`` caps single files in bytes (0 = unlimited).
    ``verbose`` adds timestamped phase lines on stderr.
    """
    phase_start = time.monotonic()
    _validate_shell(shell)
    if transfer_dir is not None and not os.path.isdir(transfer_dir):
        raise ValueError(f"--transfer-dir muss ein Verzeichnis sein: {transfer_dir}")
    if max_transfer_size < 0:
        raise ValueError("--max-transfer-size darf nicht negativ sein")
    if token is not None:
        secret, kind, auto_pin = token, "token", False
    elif pin is not None:
        secret = normalize_pin(pin)
        if not 6 <= len(secret) <= 12:
            raise ValueError("--pin braucht 6 bis 12 Ziffern")
        kind, auto_pin = "pin", False
    else:
        secret, kind, auto_pin = generate_pin(), "pin", True
    try:
        host_name = (name or socket.gethostname())[:64]
    except OSError:
        host_name = "ptt-host"
    try:
        cert_path, key_path = ensure_cert(cert_dir)
    except RuntimeError as exc:
        print(f"{err(False)} {exc}")
        raise SystemExit(1)
    fingerprint = cert_fingerprint(cert_path)
    context = tls_server_context(cert_path, key_path)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((bind, port))
        listener.listen(5)
    except OSError as exc:
        listener.close()
        print(f"{err(False)} Start fehlgeschlagen ({bind}:{port}): {exc}")
        print(
            f"{err(False)} Nächster Schritt: läuft schon ein `ptt host`? "
            "Anderen Port mit --port wählen."
        )
        raise SystemExit(1)
    actual_port = listener.getsockname()[1]
    log_phase(verbose, phase_start, f"Listener bereit ({bind}:{actual_port})")

    lan_ips = local_ips()
    color = print_banner(
        actual_port, lan_ips, host_name, secret, kind, fingerprint, discover,
        shell, color_mode,
    )
    failures: dict[str, list[float]] = {}
    session_lock = threading.Lock()
    active = [0]  # concurrent sessions, guarded by session_lock
    total = [0]  # sessions served overall, guarded by session_lock

    def _is_busy() -> bool:
        limit = 1 if once else max_sessions
        if limit <= 0:
            return False
        with session_lock:
            return active[0] >= limit

    stop_discover, discover_thread = None, None
    if discover:
        stop_discover, discover_thread = start_responder(
            actual_port, host_name, fingerprint, kind, discovery_port,
            busy=_is_busy,
        )

    err_mark, info_mark = err(color), info(color)
    if transfer_dir is not None:
        stale = cleanup_stale_parts(transfer_dir)
        if stale:
            noun = "Teil-Datei" if stale == 1 else "Teil-Dateien"
            print(
                f"{info_mark} {stale} alte {noun} aufgeräumt.",
                flush=True,
            )
    workers: list[threading.Thread] = []
    shutdown = threading.Event()

    def _session_ended(authed: bool) -> None:
        with session_lock:
            if authed:
                total[0] += 1
            live, done = active[0], total[0]
        if authed:
            print(
                f"{info_mark} Sitzungen: {live} aktiv, {done} gesamt.",
                flush=True,
            )

    def _serve_session(wrap_conn, current_secret: str) -> None:
        nonlocal secret
        try:
            authed = _handle_connection(
                wrap_conn, shell, current_secret, kind, color, failures,
                idle_timeout, max_session, shutdown, transfer_dir,
                max_transfer_size, verbose,
            )
        finally:
            try:
                wrap_conn.close()
            except OSError:
                pass
            with session_lock:
                active[0] -= 1
        _session_ended(authed)
        if authed and auto_pin:
            with session_lock:
                secret = generate_pin()
                print_banner(
                    actual_port, lan_ips, host_name, secret, kind,
                    fingerprint, discover, shell, color_mode,
                )

    if not once:
        if max_sessions > 0:
            noun = "Sitzung" if max_sessions == 1 else "Sitzungen"
            print(
                f"{info_mark} Max. {max_sessions} parallele {noun}.",
                flush=True,
            )
        else:
            print(f"{info_mark} Parallele Sitzungen: unbegrenzt.", flush=True)
    old_handlers = None
    try:
        old_handlers = _install_shutdown_handlers()
        while True:
            try:
                raw, addr = listener.accept()
            except OSError as exc:
                print(f"{err_mark} Accept-Fehler: {exc}", flush=True)
                continue
            enable_keepalive(raw)
            peer_ip = addr[0] if isinstance(addr, tuple) else str(addr)
            if _locked_out(failures, peer_ip):
                wait = _lockout_wait(failures, peer_ip)
                print(
                    f"{err_mark} Zu viele Fehlversuche von {peer_ip}, "
                    f"noch {wait:.0f} s gesperrt.",
                    flush=True,
                )
                raw.close()
                continue
            raw.settimeout(AUTH_TIMEOUT)
            try:
                conn = context.wrap_socket(raw, server_side=True)
                conn.do_handshake()
            except OSError as exc:
                if isinstance(exc, TimeoutError) or "timed out" in str(exc):
                    print(
                        f"{err_mark} TLS-Handshake Timeout ({peer_ip}).",
                        flush=True,
                    )
                else:
                    print(
                        f"{err_mark} TLS-Handshake fehlgeschlagen: {exc}",
                        flush=True,
                    )
                raw.close()
                continue
            if once:
                with session_lock:
                    active[0] += 1
                try:
                    authed = _handle_connection(
                        conn, shell, secret, kind, color, failures,
                        idle_timeout, max_session, shutdown, transfer_dir,
                        max_transfer_size, verbose,
                    )
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass
                    with session_lock:
                        active[0] -= 1
                _session_ended(authed)
                if authed and auto_pin:
                    secret = generate_pin()
                    print_banner(
                        actual_port, lan_ips, host_name, secret, kind,
                        fingerprint, discover, shell, color_mode,
                    )
                break
            with session_lock:
                busy = max_sessions > 0 and active[0] >= max_sessions
                if not busy:
                    active[0] += 1
                    current_secret = secret
            if busy:
                noun = "Sitzung" if max_sessions == 1 else "Sitzungen"
                print(
                    f"{err_mark} Verbindung von {peer_ip} abgewiesen "
                    f"(max. {max_sessions} {noun} aktiv).",
                    flush=True,
                )
                try:
                    conn.settimeout(AUTH_TIMEOUT)
                    recv_line(conn)  # discard token, else close() sends RST
                except OSError:
                    pass
                try:
                    send_line(conn, "BUSY")
                except OSError:
                    pass
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            worker = threading.Thread(
                target=_serve_session, args=(conn, current_secret), daemon=True
            )
            workers[:] = [w for w in workers if w.is_alive()]
            workers.append(worker)
            worker.start()
    except KeyboardInterrupt:
        print(f"\n{info_mark} Host beendet.", flush=True)
        shutdown.set()
        deadline = time.monotonic() + SHUTDOWN_JOIN_TIMEOUT
        for worker in workers:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            worker.join(timeout=remaining)
    finally:
        _restore_shutdown_handlers(old_handlers)
        if stop_discover is not None:
            stop_discover.set()
            discover_thread.join(timeout=2)
        listener.close()
