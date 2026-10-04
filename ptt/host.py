"""PTT host mode: open a tunnel and serve a terminal session."""
from __future__ import annotations

import hmac
import os
import secrets
import select
import socket
import ssl
import struct
import subprocess
import threading

from .cert import cert_fingerprint, ensure_cert
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


def generate_token() -> str:
    """Random token, grouped for easy typing: ``3fa2-9c1d-77b0-e4f5``."""
    return "-".join(secrets.token_hex(2) for _ in range(4))


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


def _handle_connection(conn, shell: str, token: str) -> None:
    try:
        peer = conn.getpeername()
        peer_name = f"{peer[0]}:{peer[1]}"
    except OSError:
        peer_name = "?"
    print(f"[+] Verbindung von {peer_name}", flush=True)
    conn.settimeout(AUTH_TIMEOUT)
    try:
        try:
            given = recv_line(conn).strip()
        except OSError:
            print("[-] Auth-Timeout, Verbindung geschlossen.", flush=True)
            return
        if not hmac.compare_digest(given, token):
            print(f"[-] Falsches Token von {peer_name}, abgewiesen.", flush=True)
            try:
                send_line(conn, "DENIED")
            except OSError:
                pass
            return
        send_line(conn, "OK")
        conn.settimeout(None)
        print(f"[+] Auth OK ({peer_name}), Shell startet: {shell}", flush=True)
        if HAVE_PTY:
            _serve_pty(conn, shell)
        else:
            _serve_pipes(conn, shell)
        print(f"[*] Sitzung mit {peer_name} beendet.", flush=True)
    except OSError as exc:
        print(f"[-] Verbindungsfehler ({peer_name}): {exc}", flush=True)


def run_host(
    bind: str,
    port: int,
    shell: str,
    token: str | None,
    cert_dir: str,
    once: bool = False,
) -> None:
    """Open the tunnel and serve sessions until Ctrl+C (or one if ``once``)."""
    token = token or generate_token()
    cert_path, key_path = ensure_cert(cert_dir)
    fingerprint = cert_fingerprint(cert_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind, port))
    listener.listen(5)
    actual_port = listener.getsockname()[1]

    print("=== PTT Host (Tunnel offen) ===")
    print(f"Port:          {actual_port}")
    for ip in local_ips():
        print(f"Connect:       python -m ptt connect {ip} --port {actual_port}")
    print(f"Token:         {token}")
    print(f"Fingerabdruck: {fingerprint}")
    print("Zum Beenden: Strg+C")
    print("==============================", flush=True)

    try:
        while True:
            try:
                raw, _ = listener.accept()
            except OSError as exc:
                print(f"[-] Accept-Fehler: {exc}", flush=True)
                continue
            try:
                conn = context.wrap_socket(raw, server_side=True)
                conn.do_handshake()
            except OSError as exc:
                print(f"[-] TLS-Handshake fehlgeschlagen: {exc}", flush=True)
                raw.close()
                continue
            try:
                _handle_connection(conn, shell, token)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
            if once:
                break
    except KeyboardInterrupt:
        print("\n[*] Host beendet.", flush=True)
    finally:
        listener.close()
