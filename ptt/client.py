"""PTT client mode: connect to an open tunnel."""
from __future__ import annotations

import getpass
import os
import shutil
import signal
import socket
import ssl
import struct
import sys
import threading

from .auth import normalize_pin
from .cert import peer_fingerprint
from .discover import discover
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


def _terminal_size() -> tuple[int, int]:
    size = shutil.get_terminal_size(fallback=(80, 24))
    return size.columns, size.lines


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


def _run_unix(sock) -> int:
    import select
    import termios
    import tty

    if not sys.stdin.isatty():
        print("[-] stdin ist kein Terminal; interaktiver Modus braucht ein TTY.")
        return 2
    stdin_fd = sys.stdin.fileno()
    old_attrs = termios.tcgetattr(stdin_fd)
    old_winch = None
    send_lock = threading.Lock()
    done = threading.Event()
    result = {"code": 0}

    def safe_send(ftype: int, payload: bytes) -> None:
        with send_lock:
            send_frame(sock, ftype, payload)

    def reader() -> None:
        try:
            out = sys.stdout.buffer
            while True:
                ftype, payload = recv_frame(sock)
                if ftype == FRAME_STDOUT:
                    out.write(payload)
                    out.flush()
                elif ftype == FRAME_EXIT and len(payload) == 4:
                    result["code"] = struct.unpack("!i", payload)[0]
                    break
        except OSError:
            result["code"] = 1
        finally:
            done.set()

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
        print(f"\n[-] Terminalfehler: {exc}")
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
    print(f"\n[*] Verbindung beendet (Exit-Code {result['code']}).")
    return result["code"]


def _run_windows(sock) -> int:
    import msvcrt

    _enable_windows_vt()
    done = threading.Event()
    result = {"code": 0}

    def reader() -> None:
        try:
            out = sys.stdout.buffer
            while True:
                ftype, payload = recv_frame(sock)
                if ftype == FRAME_STDOUT:
                    out.write(payload)
                    out.flush()
                elif ftype == FRAME_EXIT and len(payload) == 4:
                    result["code"] = struct.unpack("!i", payload)[0]
                    break
        except OSError:
            result["code"] = 1
        finally:
            done.set()

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
        print("[-] Verbindung abgebrochen.")
        return 1
    thread.start()
    try:
        while not done.is_set():
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
    print(f"\n[*] Verbindung beendet (Exit-Code {result['code']}).")
    return result["code"]


def pick_host(hosts: list) -> dict | None:
    """Let the user choose one discovered host (single host = auto)."""
    if len(hosts) == 1:
        only = hosts[0]
        print(f"[*] Gefunden: {only['name']} ({only['address']})")
        return only
    print("[*] Gefundene Hosts:")
    for i, host in enumerate(hosts, 1):
        print(f"  {i}) {host['name']} ({host['address']})")
    for _ in range(3):
        try:
            choice = input("Nummer wählen: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(hosts):
            return hosts[int(choice) - 1]
        print("Ungültige Auswahl.")
    return None


def _prompt_pin() -> str | None:
    for _ in range(3):
        try:
            raw = input("PIN vom Host-Bildschirm: ")
        except (EOFError, KeyboardInterrupt):
            return None
        if 4 <= len(normalize_pin(raw)) <= 12:
            return raw
        print("Bitte die PIN vom Host-Bildschirm eingeben (nur Ziffern).")
    return None


def _prompt_hidden(prompt: str) -> str | None:
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        return None


def run_client(hostname: str | None, port: int, token: str | None) -> int:
    """Connect to a host and run the interactive session. Returns exit code."""
    expected_fp: str | None = None
    auth_kind: str | None = None
    if hostname is None:
        print("[*] Suche PTT-Hosts im WLAN ...")
        hosts = discover()
        if not hosts:
            print(
                "[-] Keine PTT-Hosts gefunden. Läuft auf dem Ziel `ptt host`? "
                "Alternativ direkt: ptt connect <ip>."
            )
            return 1
        chosen = pick_host(hosts)
        if chosen is None:
            return 1
        hostname, port = chosen["address"], chosen["port"]
        expected_fp, auth_kind = chosen["fingerprint"], chosen["auth"]
    try:
        raw = socket.create_connection((hostname, port), timeout=15)
    except OSError as exc:
        print(f"[-] Keine Verbindung zu {hostname}:{port} ({exc})")
        return 1
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        sock = context.wrap_socket(raw, server_hostname=hostname)
    except OSError as exc:
        print(f"[-] TLS-Fehler: {exc}")
        raw.close()
        return 1
    peer_fp = peer_fingerprint(sock)
    print(f"[*] Host-Fingerabdruck: {peer_fp}")
    if expected_fp is not None:
        if peer_fp != expected_fp:
            print(
                "[-] Fingerabdruck stimmt NICHT mit der Ankündigung überein - "
                "Abbruch (Angriff möglich)."
            )
            sock.close()
            return 1
        print("[+] Fingerabdruck stimmt mit der Ankündigung überein.")
    else:
        print("[*] Bei Bedarf mit dem Fingerabdruck auf dem Host vergleichen.")
    secret: str | None = token
    if secret is None:
        if auth_kind == "pin":
            secret = _prompt_pin()
        elif auth_kind == "token":
            secret = _prompt_hidden("Token: ")
        else:
            secret = _prompt_hidden("PIN oder Token: ")
        if secret is None:
            print()
            sock.close()
            return 2
    try:
        send_line(sock, secret.strip())
        answer = recv_line(sock).strip()
    except OSError as exc:
        print(f"[-] Auth fehlgeschlagen ({exc})")
        sock.close()
        return 1
    if answer != "OK":
        print("[-] Zugriff verweigert (falsches Token?).")
        sock.close()
        return 1
    print("[+] Verbunden. Beenden mit `exit` in der Remote-Shell.", flush=True)
    try:
        if os.name == "nt":
            return _run_windows(sock)
        return _run_unix(sock)
    finally:
        try:
            sock.close()
        except OSError:
            pass
