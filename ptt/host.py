"""PTT host mode: open a tunnel and serve a terminal session."""
from __future__ import annotations

import hmac
import os
import select
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

from .auth import format_pin, generate_pin, normalize_pin
from .cert import cert_fingerprint, ensure_cert
from .discover import DISCOVERY_PORT, start_responder
from .protocol import (
    FRAME_EXIT,
    FRAME_RESIZE,
    FRAME_STDIN,
    FRAME_STDOUT,
    recv_frame,
    recv_line,
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

_ANSI = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "cyan": "\x1b[36m",
    "bright_green": "\x1b[92m",
}


def use_color(mode: str) -> bool:
    """Whether to emit ANSI colors (mode: auto/always/never)."""
    if mode == "always":
        return True
    if mode == "never":
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _paint(color: bool, code: str, text: str) -> str:
    if not color or not code:
        return text
    return f"{code}{text}{_ANSI['reset']}"


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
    rows.append(("", None))
    if discover_enabled:
        what = "PIN" if kind == "pin" else "Token"
        rows.append((_row("Client", f"ptt connect  ->  '{name}' wählen  ->  {what} eingeben"), None))
    else:
        rows.append((_row("Suche", "deaktiviert (direkt verbinden, s. unten)"), None))
    for ip in ips:
        rows.append((_row("Direkt", f"ptt connect {ip} --port {port}"), None))
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
    cyan = _ANSI["cyan"] if color else ""
    reset = _ANSI["reset"] if color else ""
    lines = [f"{cyan}{tl}{h * (width + 2)}{tr}{reset}"]
    for text, tag in rows:
        if tag == "title":
            content = _paint(color, _ANSI["bold"], text.ljust(width))
        elif tag == "secret":
            content = _paint(color, _ANSI["bright_green"], text.ljust(width))
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
        color=color,
        unicode_box="utf" in encoding,
    )
    print(banner, flush=True)
    return color


def _locked_out(failures: list) -> bool:
    """True after too many wrong secrets (brute-force brake for short PINs)."""
    cutoff = time.time() - PIN_WINDOW_SECONDS
    while failures and failures[0] < cutoff:
        failures.pop(0)
    return len(failures) >= PIN_MAX_FAILURES


def default_shell() -> str:
    if os.name == "nt":
        return os.environ.get("COMSPEC", "powershell.exe")
    return os.environ.get("SHELL", "/bin/bash")


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


def _serve_pty(conn, shell: str) -> None:
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

    def sock_to_pty() -> None:
        try:
            while not stop.is_set():
                ftype, payload = recv_frame(conn)
                if ftype == FRAME_STDIN:
                    os.write(master, payload)
                elif ftype == FRAME_RESIZE and len(payload) == 4:
                    cols, rows = struct.unpack("!HH", payload)
                    _set_winsize(master, cols, rows)
        except OSError:
            pass
        finally:
            stop.set()

    reader = threading.Thread(target=sock_to_pty, daemon=True)
    reader.start()
    exit_code = 0
    try:
        while True:
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
                        send_frame(conn, FRAME_STDOUT, data)
                except OSError:
                    pass
                exit_code = exited
                break
            if stop.is_set():  # client gone: stop the shell
                try:
                    proc.terminate()
                except OSError:
                    pass
                break
    finally:
        stop.set()
        try:
            send_frame(conn, FRAME_EXIT, struct.pack("!i", exit_code))
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
        reader.join(timeout=5)


def _serve_pipes(conn, shell: str) -> None:
    """Serve one session with plain pipes (fallback without PTY, e.g. Windows).

    Works for basic commands; fullscreen programs (vim, htop) need a PTY
    and will not work in this mode.
    """
    proc = subprocess.Popen(
        [shell],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    stop = threading.Event()

    def sock_to_proc() -> None:
        try:
            while not stop.is_set():
                ftype, payload = recv_frame(conn)
                if ftype == FRAME_STDIN and proc.stdin is not None:
                    proc.stdin.write(payload)
                    proc.stdin.flush()
        except (OSError, ValueError):
            pass
        finally:
            stop.set()

    reader = threading.Thread(target=sock_to_proc, daemon=True)
    reader.start()
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
            try:
                send_frame(conn, FRAME_STDOUT, data)
            except OSError:
                break
    finally:
        stop.set()
        exit_code = proc.poll()
        if exit_code is None:
            try:
                proc.terminate()
            except OSError:
                pass
            exit_code = 0
        try:
            send_frame(conn, FRAME_EXIT, struct.pack("!i", exit_code))
        except OSError:
            pass
        reader.join(timeout=5)


def _handle_connection(
    conn, shell: str, secret: str, kind: str, color: bool, failures: list
) -> bool:
    """Serve one connection. Returns True if the client authenticated."""
    ok = _paint(color, _ANSI["green"], "[+]")
    err = _paint(color, _ANSI["red"], "[-]")
    info = _paint(color, _ANSI["cyan"], "[*]")
    what = "Falsche PIN" if kind == "pin" else "Falsches Token"
    try:
        peer = conn.getpeername()
        peer_name = f"{peer[0]}:{peer[1]}"
    except OSError:
        peer_name = "?"
    print(f"{ok} Verbindung von {peer_name}", flush=True)
    conn.settimeout(AUTH_TIMEOUT)
    try:
        try:
            given = recv_line(conn).strip()
        except OSError:
            print(f"{err} Auth-Timeout, Verbindung geschlossen.", flush=True)
            return False
        if kind == "pin":
            given = normalize_pin(given)
        if not hmac.compare_digest(given, secret):
            failures.append(time.time())
            print(f"{err} {what} von {peer_name}, abgewiesen.", flush=True)
            try:
                send_line(conn, "DENIED")
            except OSError:
                pass
            return False
        send_line(conn, "OK")
        conn.settimeout(None)
        print(f"{ok} Auth OK ({peer_name}), Shell startet: {shell}", flush=True)
        if HAVE_PTY:
            _serve_pty(conn, shell)
        else:
            _serve_pipes(conn, shell)
        print(f"{info} Sitzung mit {peer_name} beendet.", flush=True)
        return True
    except OSError as exc:
        print(f"{err} Verbindungsfehler ({peer_name}): {exc}", flush=True)
        return False


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
) -> None:
    """Open the tunnel and serve sessions until Ctrl+C (or one if ``once``)."""
    if token is not None:
        secret, kind, auto_pin = token, "token", False
    elif pin is not None:
        secret = normalize_pin(pin)
        if len(secret) < 4:
            raise ValueError("--pin braucht mindestens 4 Ziffern")
        kind, auto_pin = "pin", False
    else:
        secret, kind, auto_pin = generate_pin(), "pin", True
    try:
        host_name = (name or socket.gethostname())[:64]
    except OSError:
        host_name = "ptt-host"
    cert_path, key_path = ensure_cert(cert_dir)
    fingerprint = cert_fingerprint(cert_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind, port))
    listener.listen(5)
    actual_port = listener.getsockname()[1]

    lan_ips = local_ips()
    color = print_banner(
        actual_port, lan_ips, host_name, secret, kind, fingerprint, discover,
        color_mode,
    )
    failures: list = []
    stop_discover, discover_thread = None, None
    if discover:
        stop_discover, discover_thread = start_responder(
            actual_port, host_name, fingerprint, kind, discovery_port
        )

    err = _paint(color, _ANSI["red"], "[-]")
    info = _paint(color, _ANSI["cyan"], "[*]")
    try:
        while True:
            try:
                raw, _ = listener.accept()
            except OSError as exc:
                print(f"{err} Accept-Fehler: {exc}", flush=True)
                continue
            if _locked_out(failures):
                print(f"{err} Zu viele Fehlversuche, kurz gesperrt.", flush=True)
                raw.close()
                continue
            try:
                conn = context.wrap_socket(raw, server_side=True)
                conn.do_handshake()
            except OSError as exc:
                print(f"{err} TLS-Handshake fehlgeschlagen: {exc}", flush=True)
                raw.close()
                continue
            try:
                authed = _handle_connection(
                    conn, shell, secret, kind, color, failures
                )
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
            if authed and auto_pin and not once:
                secret = generate_pin()
                print_banner(
                    actual_port, lan_ips, host_name, secret, kind, fingerprint,
                    discover, color_mode,
                )
            if once:
                break
    except KeyboardInterrupt:
        print(f"\n{info} Host beendet.", flush=True)
    finally:
        if stop_discover is not None:
            stop_discover.set()
            discover_thread.join(timeout=2)
        listener.close()
