"""PTT self-check: environment diagnosis for users (`ptt doctor`)."""
from __future__ import annotations

import contextlib
import datetime
import io
import json
import os
import platform
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types

from . import __version__
from .cert import (
    CERT_FILE,
    KEY_FILE,
    _pem_files_valid,
    default_cert_dir,
    ensure_cert,
    tls_server_context,
)
from .client import run_client, run_exec
from .discover import DISCOVER_REQUEST, DISCOVERY_PORT
from .host import DEFAULT_PORT, _validate_shell, default_shell, run_host
from .output import format_bytes

#: Warn when the host certificate expires within this many days.
CERT_EXPIRY_WARN_DAYS = 30

#: Warn when less than this many bytes are free on the transfer volume.
MIN_FREE_BYTES = 100 * 1024**2

#: Hard cap for the whole self-test (it must never hang doctor).
#: Budget: 3 steps x STEP timeout + cert/host overhead (see test).
SELF_TEST_TIMEOUT = 90.0

#: Per-step client timeout inside the self-test.
SELF_TEST_STEP_TIMEOUT = 20.0

#: Token for self-test sessions (long on purpose: no warnings).
SELF_TEST_TOKEN = "self-test-token-0123456789"

#: Hint for failed self-test steps (points back at plain doctor).
_SELF_FAIL_HINT = (
    "Umgebung prüfen mit `ptt doctor`; bleibt der Fehler, "
    "Netzwerk und Firewall prüfen."
)

#: IPv4 matcher for report redaction (octets validated in code).
_IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def _display(path: str) -> str:
    """Shorten paths under $HOME to ``~/...``."""
    home = os.path.expanduser("~")
    if path == home:
        return "~"
    if path.startswith(home + os.sep):
        return "~" + path[len(home):]
    return path


def _check_python(cert_dir: str) -> tuple[str, str]:
    """Python version; ``cert_dir`` unused (uniform check signature)."""
    version = sys.version_info
    text = f"Python {version.major}.{version.minor}.{version.micro}"
    if version < (3, 9):
        return ("FAIL", f"{text} (mind. 3.9 nötig)")
    return ("OK", text)


def _check_tls_backend(cert_dir: str) -> tuple[str, str]:
    """TLS tooling; ``cert_dir`` unused (uniform check signature)."""
    if shutil.which("openssl"):
        return ("OK", "openssl gefunden")
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return (
            "WARN",
            "weder openssl noch cryptography (für `ptt host` nötig)",
        )
    return ("OK", "cryptography-Paket gefunden")


def _check_cert_dir(cert_dir: str) -> tuple[str, str]:
    shown = _display(cert_dir)
    if not os.path.exists(cert_dir):
        return ("OK", f"{shown} (wird beim ersten Host-Start angelegt)")
    if os.name != "nt" and stat.S_IMODE(os.stat(cert_dir).st_mode) != 0o700:
        return ("WARN", f"{shown} (Rechte sollten 0700 sein)")
    return ("OK", shown)


def _check_cert_files(cert_dir: str) -> tuple[str, str]:
    cert_path = os.path.join(cert_dir, CERT_FILE)
    key_path = os.path.join(cert_dir, KEY_FILE)
    if not os.path.exists(cert_path) and not os.path.exists(key_path):
        return ("OK", "Zertifikat (wird beim ersten Host-Start erzeugt)")
    if _pem_files_valid(cert_path, key_path):
        return ("OK", "Zertifikat gültig")
    return ("WARN", "Zertifikat ungültig (wird neu erzeugt)")


def _as_utc(moment: datetime.datetime) -> datetime.datetime:
    """Normalize a parsed end date to aware UTC (assumes UTC when naive)."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=datetime.timezone.utc)
    return moment.astimezone(datetime.timezone.utc)


def _expiry_with_cryptography(cert_path: str):
    """Certificate end date via the cryptography package, if usable."""
    from cryptography import x509

    with open(cert_path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    moment = getattr(cert, "not_valid_after_utc", None)
    if moment is None:  # older cryptography: naive UTC property
        moment = cert.not_valid_after
    return _as_utc(moment)


def _expiry_with_openssl(cert_path: str):
    """Certificate end date via the openssl binary, if usable."""
    if shutil.which("openssl") is None:
        return None
    proc = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-enddate", "-noout"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if proc.returncode != 0:
        return None
    text = proc.stdout.strip()
    if not text.startswith("notAfter="):
        return None
    moment = datetime.datetime.strptime(
        text[len("notAfter="):], "%b %d %H:%M:%S %Y %Z"
    )
    return _as_utc(moment)


def _cert_expiry(cert_path: str):
    """Certificate end date (aware UTC), or None when not parseable."""
    for probe in (_expiry_with_cryptography, _expiry_with_openssl):
        try:
            found = probe(cert_path)
        except (ImportError, OSError, ValueError, subprocess.SubprocessError):
            continue
        if found is not None:
            return found
    return None


def _check_cert_expiry(cert_dir: str) -> tuple[str, str]:
    cert_path = os.path.join(cert_dir, CERT_FILE)
    if not os.path.exists(cert_path):
        return ("OK", "Ablauf (noch kein Zertifikat, wird erzeugt)")
    end = _cert_expiry(cert_path)
    if end is None:
        return (
            "WARN",
            "Ablauf nicht prüfbar (weder openssl noch cryptography)",
        )
    now = datetime.datetime.now(datetime.timezone.utc)
    if end <= now:
        return (
            "WARN",
            f"Zertifikat abgelaufen (in {_display(cert_dir)} löschen, "
            "Host neu starten)",
        )
    days = (end - now).days
    if days < CERT_EXPIRY_WARN_DAYS:
        when = "heute" if days == 0 else f"in {days} Tagen"
        return (
            "WARN",
            f"Zertifikat läuft {when} ab ({end:%Y-%m-%d})",
        )
    return ("OK", f"Zertifikat gültig bis {end:%Y-%m-%d} ({days} Tage)")


def _check_cert_key(cert_dir: str) -> tuple[str, str]:
    cert_path = os.path.join(cert_dir, CERT_FILE)
    key_path = os.path.join(cert_dir, KEY_FILE)
    missing = [
        name
        for path, name in ((cert_path, "Zertifikat"), (key_path, "Schlüssel"))
        if not os.path.exists(path)
    ]
    if len(missing) == 2:
        return ("OK", "Schlüsselpaar (wird mit dem Zertifikat erzeugt)")
    if missing:
        return (
            "FAIL",
            f"unvollständig ({missing[0]} fehlt; beide Dateien in "
            f"{_display(cert_dir)} löschen, Host neu starten)",
        )
    if not _pem_files_valid(cert_path, key_path):
        return (
            "FAIL",
            f"nicht ladbar (beide Dateien in {_display(cert_dir)} "
            "löschen, Host neu starten)",
        )
    try:
        tls_server_context(cert_path, key_path)
    except (ssl.SSLError, OSError) as exc:
        return (
            "FAIL",
            f"passen nicht zusammen ({exc}; beide Dateien in "
            f"{_display(cert_dir)} löschen, Host neu starten)",
        )
    return ("OK", "Zertifikat und Schlüssel passen zusammen")


def _port_free(port: int, kind: int) -> bool:
    try:
        probe = socket.socket(socket.AF_INET, kind)
    except OSError:
        return False
    try:
        probe.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _check_ports(cert_dir: str) -> tuple[str, str]:
    """Default ports free; ``cert_dir`` unused (uniform check signature)."""
    busy = []
    if not _port_free(DEFAULT_PORT, socket.SOCK_STREAM):
        busy.append(f"TCP {DEFAULT_PORT}")
    if not _port_free(DISCOVERY_PORT, socket.SOCK_DGRAM):
        busy.append(f"UDP {DISCOVERY_PORT}")
    if not busy:
        return ("OK", f"TCP {DEFAULT_PORT} + UDP {DISCOVERY_PORT} frei")
    return ("WARN", f"{', '.join(busy)} belegt (läuft schon ein Host?)")


def _check_net_tcp(cert_dir: str) -> tuple[str, str]:
    """TCP loopback works; ``cert_dir`` unused (uniform check signature)."""
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        return ("FAIL", f"TCP-Loopback gestört ({exc})")
    try:
        listener.settimeout(5)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except OSError as exc:
            return ("FAIL", f"TCP-Loopback gestört ({exc})")
        try:
            client.settimeout(5)
            client.connect(listener.getsockname())
            conn, _ = listener.accept()
            conn.close()
        finally:
            client.close()
    except OSError as exc:
        return ("FAIL", f"TCP-Loopback gestört ({exc})")
    finally:
        listener.close()
    return ("OK", "TCP-Loopback ok")


def _check_net_udp(cert_dir: str) -> tuple[str, str]:
    """UDP broadcast sendable; ``cert_dir`` unused (uniform signature)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as exc:
        return (
            "WARN",
            f"UDP-Broadcast nicht sendbar ({exc}); "
            "direkt verbinden: ptt connect <ip>",
        )
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(DISCOVER_REQUEST, ("255.255.255.255", DISCOVERY_PORT))
    except OSError as exc:
        return (
            "WARN",
            f"UDP-Broadcast nicht sendbar ({exc}); "
            "direkt verbinden: ptt connect <ip>",
        )
    finally:
        sock.close()
    return ("OK", "UDP-Broadcast sendbar (Suche möglich)")


def _check_shell(cert_dir: str) -> tuple[str, str]:
    """Default shell usable; ``cert_dir`` unused (uniform check signature)."""
    shell = default_shell()
    try:
        _validate_shell(shell)
    except ValueError:
        return ("WARN", f"{shell} (nicht ausführbar, für `ptt host` nötig)")
    return ("OK", f"Shell: {shell}")


def _transfer_target() -> str:
    """Probed transfer dir: the working directory (the host default)."""
    return os.getcwd()


def _check_transfer_dir(cert_dir: str) -> tuple[str, str]:
    """Transfer dir writable; ``cert_dir`` unused (uniform signature)."""
    try:
        target = _transfer_target()
        if not os.path.isdir(target):
            return ("FAIL", f"{_display(target)}: kein Verzeichnis")
        with tempfile.NamedTemporaryFile(
            dir=target, prefix=".ptt-write-"
        ):
            pass
    except OSError as exc:
        return ("FAIL", f"Transfer-Verzeichnis nicht beschreibbar ({exc})")
    return ("OK", f"Transfer-Verzeichnis {_display(target)}: beschreibbar")


def _check_disk_space(cert_dir: str) -> tuple[str, str]:
    """Enough free space; ``cert_dir`` unused (uniform check signature)."""
    try:
        target = _transfer_target()
        usage = shutil.disk_usage(target)
    except OSError as exc:
        return ("WARN", f"Plattenplatz nicht prüfbar ({exc})")
    if usage.free < MIN_FREE_BYTES:
        return (
            "WARN",
            f"wenig Plattenplatz frei ({format_bytes(usage.free)} "
            f"von {format_bytes(usage.total)})",
        )
    return ("OK", f"Plattenplatz ok ({format_bytes(usage.free)} frei)")


def _check_stale_parts(cert_dir: str) -> tuple[str, str]:
    """Count resume parts; ``cert_dir`` unused (uniform check signature)."""
    try:
        target = _transfer_target()
        names = os.listdir(target)
    except OSError as exc:
        return ("WARN", f"Teil-Dateien nicht prüfbar ({exc})")
    parts = [
        name
        for name in names
        if name.endswith(".ptt-part")
        and os.path.isfile(os.path.join(target, name))
    ]
    if not parts:
        return ("OK", "keine Teil-Dateien")
    noun = "Teil-Datei" if len(parts) == 1 else "Teil-Dateien"
    return (
        "OK",
        f"{len(parts)} {noun} (Resume-Material, unbedenklich)",
    )


#: All checks as (id, title, function, hint); order is the display order.
#: The hint is the next step shown for WARN/FAIL results.
CHECKS = [
    (
        "python",
        "Python-Version",
        _check_python,
        "Python 3.9 oder neuer installieren "
        "(python.org, Paketmanager, winget).",
    ),
    (
        "tls-backend",
        "TLS-Werkzeug",
        _check_tls_backend,
        "openssl installieren oder: "
        "python3 -m pip install cryptography.",
    ),
    (
        "cert-dir",
        "Zertifikat-Verzeichnis",
        _check_cert_dir,
        "Mit `ptt doctor --fix` die Rechte korrigieren.",
    ),
    (
        "cert",
        "Zertifikat",
        _check_cert_files,
        "Zertifikat-Verzeichnis löschen — "
        "`ptt host` erzeugt es neu.",
    ),
    (
        "cert-expiry",
        "Zertifikat-Ablauf",
        _check_cert_expiry,
        "Läuft ab: Zertifikat-Verzeichnis löschen, Host neu "
        "starten. Nicht prüfbar: openssl installieren.",
    ),
    (
        "cert-key",
        "Zertifikat-Schlüssel",
        _check_cert_key,
        "Beide Dateien im Zertifikat-Verzeichnis löschen, "
        "`ptt host` neu starten.",
    ),
    (
        "ports",
        "Ports",
        _check_ports,
        "Port freigeben (anderen Host beenden) oder: "
        "`ptt host --port 9000`.",
    ),
    (
        "net-tcp",
        "TCP-Loopback",
        _check_net_tcp,
        "Firewall und Netzwerk prüfen — Loopback "
        "(127.0.0.1) muss offen sein.",
    ),
    (
        "net-udp",
        "UDP-Broadcast",
        _check_net_udp,
        "Ohne Suche direkt verbinden: `ptt connect <IP>`.",
    ),
    (
        "shell",
        "Shell",
        _check_shell,
        "Andere Shell wählen: `ptt host --shell /bin/sh`.",
    ),
    (
        "transfer-dir",
        "Transfer-Verzeichnis",
        _check_transfer_dir,
        "In ein beschreibbares Verzeichnis wechseln oder "
        "`--transfer-dir` setzen.",
    ),
    (
        "disk-space",
        "Plattenplatz",
        _check_disk_space,
        "Platz schaffen oder `--transfer-dir` auf ein Volume "
        "mit Platz legen.",
    ),
    (
        "stale-parts",
        "Transfer-Teile",
        _check_stale_parts,
        "Abgebrochene Transfers neu senden oder die "
        "`.ptt-part`-Dateien löschen.",
    ),
]


def run_checks(cert_dir: str | None = None) -> list[tuple[str, str]]:
    """Run all checks; returns [(status, message)] with OK/WARN/FAIL."""
    return [
        (check["status"], check["message"])
        for check in run_checks_detailed(cert_dir)
    ]


def run_checks_detailed(
    cert_dir: str | None = None,
    only: list[str] | None = None,
) -> list[dict]:
    """Run checks (all, or the ``only`` ids, in registry order).

    Returns [{id, title, status, message, hint}].
    """
    directory = cert_dir or default_cert_dir()
    wanted = set(only) if only else None
    results = []
    for check_id, title, func, hint in CHECKS:
        if wanted is not None and check_id not in wanted:
            continue
        status, message = func(directory)
        results.append(
            {
                "id": check_id,
                "title": title,
                "status": status,
                "message": message,
                "hint": hint,
            }
        )
    return results


def redact(text: str) -> str:
    """Scrub support-report text: home dir becomes ~, LAN IPs <ip>.

    Loopback (127.x) stays readable — it carries no identity.
    """
    home = os.path.expanduser("~")
    if home and home not in ("~", "/"):
        text = text.replace(home, "~")

    def _scrub_ip(match: re.Match) -> str:
        groups = match.groups()
        if any(int(part) > 255 for part in groups):
            return match.group(0)
        if groups[0] == "127":
            return match.group(0)
        return "<ip>"

    return _IPV4_RE.sub(_scrub_ip, text)


def render_report(results: list[dict]) -> str:
    """Render check results as a redacted Markdown report."""
    fails = sum(1 for check in results if check["status"] == "FAIL")
    warns = sum(1 for check in results if check["status"] == "WARN")
    version = sys.version_info
    stamp = datetime.datetime.now(datetime.timezone.utc)
    lines = [
        "# PTT-Diagnosebericht",
        "",
        f"- PTT: {__version__}",
        f"- Python: {version.major}.{version.minor}.{version.micro}",
        f"- System: {platform.system()} {platform.release()}",
        f"- Datum (UTC): {stamp:%Y-%m-%d %H:%M}",
        f"- Ergebnis: {fails} Fehler, {warns} Warnungen",
        "",
        "## Prüfungen",
        "",
    ]
    for check in results:
        lines.append(
            f"- [{check['status']}] {check['id']}: {check['message']}"
        )
        hint = check.get("hint")
        if hint and check["status"] != "OK":
            lines.append(f"  Hinweis: {hint}")
    lines += [
        "",
        "Hinweis: Heimverzeichnis und IP-Adressen wurden "
        "aus diesem Bericht entfernt.",
        "",
    ]
    return redact("\n".join(lines))


def run_report(
    cert_dir: str | None = None, path: str | None = None
) -> int:
    """Write/print a redacted Markdown report; 0 when no FAIL, else 1.

    ``path`` None/"-" prints to stdout, anything else is a file.
    """
    results = run_checks_detailed(cert_dir)
    body = render_report(results) + "\n"
    failed = any(check["status"] == "FAIL" for check in results)
    if path is None or path == "-":
        print(body, end="")
        return 1 if failed else 0
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body)
    except OSError as exc:
        print(f"[-] Bericht scheitert: {exc}")
        return 1
    print(f"[+] Bericht geschrieben: {_display(path)}")
    return 1 if failed else 0


def list_checks(as_json: bool = False) -> int:
    """List all check IDs with titles; always returns 0."""
    if as_json:
        print(
            json.dumps(
                [
                    {"id": i, "title": t, "hint": h}
                    for i, t, _, h in CHECKS
                ],
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    print(f"[*] PTT-Prüfungen ({len(CHECKS)})")
    for check_id, title, _, _ in CHECKS:
        print(f"  {check_id}: {title}")
    print("[*] Auswahl prüfen: ptt doctor --check <id>[,<id>...]")
    return 0


def run_doctor(
    cert_dir: str | None = None,
    as_json: bool = False,
    self_test: bool = False,
    only: list[str] | None = None,
) -> int:
    """Print the diagnosis; 0 when no FAIL, else 1."""
    if self_test:
        if not as_json:
            print("[*] PTT-Selbsttest (dauert einige Sekunden) ...",
                  flush=True)
        results = run_self_test()
    else:
        results = run_checks_detailed(cert_dir, only=only)
    fails = sum(1 for check in results if check["status"] == "FAIL")
    warns = sum(1 for check in results if check["status"] == "WARN")
    if as_json:
        print(
            json.dumps(
                {
                    "checks": results,
                    "fails": fails,
                    "warns": warns,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 1 if fails else 0
    print("[*] PTT-Selbsttest" if self_test else "[*] PTT-Diagnose")
    for check in results:
        print(f"[{check['status']}] {check['message']}")
        hint = check.get("hint")
        if hint and check["status"] != "OK":
            print(f"  Hinweis: {hint}")
    if fails:
        print(f"[-] {fails} Problem(e), {warns} Warnung(en).")
        return 1
    if warns:
        print(f"[*] Bereit mit {warns} Warnung(en).")
    else:
        print("[+] Alles bereit.")
    return 0


def _fix_data_perms(
    cert_dir: str, dry_run: bool
) -> tuple[str, str]:
    """Tighten permissions under ``cert_dir`` (dirs 0700, files 0600).

    Never follows symlinks; returns (status, message) with status
    OK (already correct), FIXED, TODO (dry run) or FAIL.
    """
    if not os.path.exists(cert_dir):
        return ("OK", f"{_display(cert_dir)}: nicht vorhanden, nichts zu tun")
    checked, fixed, skipped = 0, 0, []
    failed: list[str] = []

    def _visit(path: str, want: int) -> None:
        nonlocal checked, fixed
        if os.path.islink(path):
            skipped.append(path)
            return
        checked += 1
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
        except OSError as exc:
            failed.append(f"{path}: {exc}")
            return
        if mode == want:
            return
        if dry_run:
            fixed += 1
            return
        try:
            os.chmod(path, want)
        except OSError as exc:
            failed.append(f"{path}: {exc}")
            return
        fixed += 1

    _visit(cert_dir, 0o700)
    for root, dirs, files in os.walk(cert_dir, followlinks=False):
        for name in dirs:
            _visit(os.path.join(root, name), 0o700)
        for name in files:
            _visit(os.path.join(root, name), 0o600)
    shown = _display(cert_dir)
    if failed:
        return (
            "FAIL",
            f"{shown}: {failed[0]} "
            f"({len(failed)} von {checked} fehlgeschlagen)",
        )
    if fixed:
        if dry_run:
            status = "TODO"
            message = (
                f"{shown}: würde Rechte korrigieren "
                f"({fixed} von {checked} geprüft)"
            )
        else:
            status = "FIXED"
            message = (
                f"{shown}: Rechte korrigiert ({fixed} von {checked} geprüft)"
            )
    else:
        status = "OK"
        message = f"{shown}: Rechte korrekt ({checked} geprüft)"
    if skipped:
        noun = "Symlink" if len(skipped) == 1 else "Symlinks"
        message += f"; {len(skipped)} {noun} übersprungen"
    return (status, message)


#: All fixes as (id, title, function); order is the display order.
FIXES = [
    ("data-perms", "Datenverzeichnis-Rechte", _fix_data_perms),
]


def run_fix(
    cert_dir: str | None = None, dry_run: bool = False
) -> int:
    """Apply safe fixes; 0 when all good, else 1. Never raises."""
    if os.name == "nt":
        print("[*] Windows verwaltet Dateirechte anders; nichts zu tun.")
        return 0
    directory = cert_dir or default_cert_dir()
    header = "[*] PTT-Reparatur"
    if dry_run:
        header += " (Vorschau, nichts geändert)"
    print(header)
    failed = 0
    for _fix_id, _title, func in FIXES:
        try:
            status, message = func(directory, dry_run)
        except OSError as exc:
            status, message = "FAIL", f"{directory}: {exc}"
        print(f"[{status}] {message}")
        if status == "FAIL":
            failed += 1
    if not failed and not dry_run:
        print("[*] Danach erneut prüfen mit: ptt doctor")
    return 1 if failed else 0


def _free_tcp_port() -> int:
    """A currently free loopback TCP port (bind-0 trick)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def _wait_for_port(port: int, timeout: float = 10.0) -> bool:
    """True once something accepts on ``port`` (probe, then close)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            probe = socket.create_connection(
                ("127.0.0.1", port), timeout=1
            )
        except OSError:
            time.sleep(0.1)
            continue
        probe.close()
        return True
    return False


@contextlib.contextmanager
def _isolated_home(tmp: str):
    """Point HOME/USERPROFILE at ``tmp`` (TOFU stays out of ~/.ptt)."""
    old = {}
    for key in ("HOME", "USERPROFILE"):
        old[key] = os.environ.get(key)
        os.environ[key] = tmp
    try:
        yield
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextlib.contextmanager
def _empty_stdin():
    """Empty stdin for self-test clients (never block on the terminal)."""
    old = sys.stdin
    sys.stdin = types.SimpleNamespace(buffer=io.BytesIO(b""))
    try:
        yield
    finally:
        sys.stdin = old


@contextlib.contextmanager
def _captured_bytes():
    """Capture stdout as bytes (keeps a .buffer for session payload)."""
    raw = io.BytesIO()
    wrapper = io.TextIOWrapper(raw, encoding="utf-8")
    old = sys.stdout
    sys.stdout = wrapper
    try:
        yield raw
    finally:
        # Flush + detach: the exhausted generator drops ``wrapper``,
        # whose GC would otherwise close ``raw`` with it.
        with contextlib.suppress(ValueError):
            wrapper.flush()
        with contextlib.suppress(ValueError):
            wrapper.detach()
        sys.stdout = old


def _self_test_host(
    port: int, cert_dir: str, transfer_dir: str
) -> threading.Thread:
    """Start a one-shot self-test host; returns the thread."""
    thread = threading.Thread(
        target=run_host,
        kwargs={
            "bind": "127.0.0.1",
            "port": port,
            "shell": default_shell(),
            "token": SELF_TEST_TOKEN,
            "cert_dir": cert_dir,
            "once": True,
            "color_mode": "never",
            "discover": False,
            "transfer_dir": transfer_dir,
        },
        daemon=True,
    )
    thread.start()
    return thread


def _self_test_steps() -> list[dict]:
    """Run the self-test steps; returns rows like the check registry."""
    rows: list[dict] = []

    def _row(
        step_id: str,
        title: str,
        status: str,
        message: str,
        hint: str = "",
    ) -> None:
        rows.append(
            {
                "id": step_id,
                "title": title,
                "status": status,
                "message": message,
                "hint": hint,
            }
        )

    with tempfile.TemporaryDirectory() as tmp:
        cert_dir = os.path.join(tmp, "certs")
        transfer_dir = os.path.join(tmp, "transfer")
        os.mkdir(transfer_dir)
        work = os.path.join(tmp, "work")
        os.mkdir(work)
        try:
            ensure_cert(cert_dir)
        except RuntimeError as exc:
            _row(
                "self-cert", "Selbsttest: Zertifikat", "FAIL",
                f"Test-Zertifikat scheitert ({exc})",
                hint="TLS-Werkzeug fehlt? Siehe "
                "`ptt doctor --check tls-backend`.",
            )
            return rows
        _row(
            "self-cert", "Selbsttest: Zertifikat", "OK",
            "Test-Zertifikat erzeugt",
        )
        payload = b"self-test-payload-42"
        src = os.path.join(work, "up.bin")
        with open(src, "wb") as fh:
            fh.write(payload)
        with _isolated_home(tmp), _empty_stdin():
            _self_test_exec(rows, _row, cert_dir, transfer_dir)
            _self_test_put(
                rows, _row, cert_dir, transfer_dir, src, payload
            )
            _self_test_get(
                rows, _row, cert_dir, transfer_dir, work, payload
            )
    return rows


def _self_test_exec(rows, _row, cert_dir: str, transfer_dir: str) -> None:
    """Self-test step: one remote command roundtrip."""
    port = _free_tcp_port()
    with _captured_bytes() as raw:
        thread = _self_test_host(port, cert_dir, transfer_dir)
        if not _wait_for_port(port):
            thread.join(timeout=5)
            _row(
                "self-exec", "Selbsttest: exec", "FAIL",
                "Host startet nicht (Timeout)",
                hint=_SELF_FAIL_HINT,
            )
            return
        rc = run_exec(
            "127.0.0.1", port, SELF_TEST_TOKEN, "never",
            argv=[sys.executable, "-c", "print('self-ok')"],
            timeout=SELF_TEST_STEP_TIMEOUT,
        )
        thread.join(timeout=15)
    out = raw.getvalue().decode("utf-8", "replace")
    if rc == 0 and "self-ok" in out:
        _row("self-exec", "Selbsttest: exec", "OK", "exec ok")
    else:
        _row(
            "self-exec", "Selbsttest: exec", "FAIL",
            f"exec scheitert (Exit {rc})",
            hint=_SELF_FAIL_HINT,
        )


def _self_test_put(
    rows, _row, cert_dir: str, transfer_dir: str, src: str, payload: bytes
) -> None:
    """Self-test step: upload one file and verify its bytes."""
    port = _free_tcp_port()
    with _captured_bytes():
        thread = _self_test_host(port, cert_dir, transfer_dir)
        if not _wait_for_port(port):
            thread.join(timeout=5)
            _row(
                "self-put", "Selbsttest: Upload", "FAIL",
                "Host startet nicht (Timeout)",
                hint=_SELF_FAIL_HINT,
            )
            return
        rc = run_client(
            "127.0.0.1", port, SELF_TEST_TOKEN, "never",
            put=src, timeout=SELF_TEST_STEP_TIMEOUT,
        )
        thread.join(timeout=15)
    landed = os.path.join(transfer_dir, os.path.basename(src))
    ok = rc == 0
    if ok:
        try:
            with open(landed, "rb") as fh:
                ok = fh.read() == payload
        except OSError:
            ok = False
    if ok:
        _row("self-put", "Selbsttest: Upload", "OK", "Upload ok")
    else:
        _row(
            "self-put", "Selbsttest: Upload", "FAIL",
            f"Upload scheitert (Exit {rc})",
            hint=_SELF_FAIL_HINT,
        )


def _self_test_get(
    rows, _row, cert_dir: str, transfer_dir: str, work: str, payload: bytes
) -> None:
    """Self-test step: download the uploaded file and verify it."""
    port = _free_tcp_port()
    local = os.path.join(work, "down.bin")
    with _captured_bytes():
        thread = _self_test_host(port, cert_dir, transfer_dir)
        if not _wait_for_port(port):
            thread.join(timeout=5)
            _row(
                "self-get", "Selbsttest: Download", "FAIL",
                "Host startet nicht (Timeout)",
                hint=_SELF_FAIL_HINT,
            )
            return
        rc = run_client(
            "127.0.0.1", port, SELF_TEST_TOKEN, "never",
            get=f"up.bin:{local}", timeout=SELF_TEST_STEP_TIMEOUT,
        )
        thread.join(timeout=15)
    ok = rc == 0
    if ok:
        try:
            with open(local, "rb") as fh:
                ok = fh.read() == payload
        except OSError:
            ok = False
    if ok:
        _row("self-get", "Selbsttest: Download", "OK", "Download ok")
    else:
        _row(
            "self-get", "Selbsttest: Download", "FAIL",
            f"Download scheitert (Exit {rc})",
            hint=_SELF_FAIL_HINT,
        )


def run_self_test() -> list[dict]:
    """Run the self-test steps with a hard timeout. Never hangs."""
    rows: list[dict] = []
    worker = threading.Thread(
        target=lambda: rows.extend(_self_test_steps()), daemon=True
    )
    worker.start()
    worker.join(timeout=SELF_TEST_TIMEOUT)
    if worker.is_alive():
        rows.append(
            {
                "id": "self-timeout",
                "title": "Selbsttest: Timeout",
                "status": "FAIL",
                "message": "Selbsttest hängt "
                f"(>{SELF_TEST_TIMEOUT:.0f} s abgebrochen)",
                "hint": "Erneut versuchen; bleibt der Test hängen, "
                "Netzwerk und Firewall prüfen.",
            }
        )
    return list(rows)
