"""PTT command line interface."""
from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable

from . import __version__
from .cert import default_cert_dir
from .client import run_client, run_exec, run_scan
from .doctor import (
    CHECKS,
    list_checks,
    run_doctor,
    run_fix,
    run_report,
)
from .host import DEFAULT_PORT, default_shell, run_host
from .transfer import parse_size
from .reset import run_reset
from .update import run_update


def _validate_port(value: str) -> int:
    """Argparse type: port number between 1 and 65535."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"ungültiger Port: {value!r}")
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(
            f"Port muss zwischen 1 und 65535 liegen: {port}"
        )
    return port


def _resolve_token(flag: str | None, file: str | None) -> str | None:
    """Resolve the token: CLI flag > PTT_TOKEN env > token file > None.

    None means "ask interactively". Raises ValueError for unreadable files.
    """
    if flag is not None:
        print(
            "Warnung: --token per CLI ist per `ps` sichtbar; "
            "lieber PTT_TOKEN oder --token-file nutzen.",
            file=sys.stderr,
        )
        return flag
    env = os.environ.get("PTT_TOKEN")
    if env:
        return env
    if file is not None:
        try:
            with open(file, encoding="utf-8") as f:
                content = f.read().strip()
        except OSError as exc:
            raise ValueError(f"--token-file nicht lesbar: {file} ({exc})")
        if not content:
            raise ValueError(f"--token-file ist leer: {file}")
        return content
    return None


def _warn_short_token(token: str | None) -> None:
    """Warn when a host token is short (host side only, PINs unaffected)."""
    if token is not None and len(token) < 16:
        print(
            "Warnung: Token ist kurz (< 16 Zeichen); "
            "für unsichere Netze langes Token empfohlen.",
            file=sys.stderr,
        )


def _add_port_arg(subparser, what: str) -> None:
    """Add the shared ``--port`` argument (env fallback: PTT_PORT)."""
    subparser.add_argument(
        "--port",
        type=_validate_port,
        default=None,
        help=f"{what} (Default: {DEFAULT_PORT}, Env: PTT_PORT)",
    )


def _parse_timeout(raw: str) -> float:
    """Parse a timeout value from text: float, not negative."""
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"keine Zahl: {raw!r}")
    if value < 0:
        raise ValueError("darf nicht negativ sein")
    return value


def _parse_check_ids(
    parser: argparse.ArgumentParser, raw: str
) -> list[str]:
    """Parse ``--check ID[,ID...]``; unknown IDs fail with exit code 2."""
    valid = [check_id for check_id, _, _, _ in CHECKS]
    wanted = [part.strip() for part in raw.split(",")]
    wanted = [part for part in wanted if part]
    if not wanted:
        parser.error("--check braucht mindestens eine Prüf-ID")
    for check_id in wanted:
        if check_id not in valid:
            parser.error(
                f"unbekannte Prüfung: {check_id} "
                f"(wähle aus: {', '.join(valid)})"
            )
    return [check_id for check_id in valid if check_id in wanted]


def _resolve_opt(
    cli_value: str | int | float | None,
    env_name: str,
    parse: Callable[[str], str | int | float] | None,
    default: str | int | float | None,
    parser: argparse.ArgumentParser,
) -> str | int | float | None:
    """Resolve an option: CLI flag wins, then environment, then default.

    ``parse`` converts the env text (None = plain string); empty env
    values count as unset. Bad env values fail with exit code 2 naming
    the variable (a typo'd env must never silently connect elsewhere).
    """
    if cli_value is not None:
        return cli_value
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return default
    if parse is None:
        return raw
    try:
        return parse(raw)
    except (ValueError, argparse.ArgumentTypeError) as exc:
        parser.error(f"{env_name}: {exc}")


def _add_color_arg(subparser) -> None:
    """Add the shared ``--color`` argument (auto/always/never)."""
    subparser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Farbige Ausgabe (Default: auto)",
    )


def _add_quiet_arg(subparser) -> None:
    """Add the shared ``--quiet`` flag (status to stderr, for scripts)."""
    subparser.add_argument(
        "--quiet",
        action="store_true",
        help="Ruhig: Status nach stderr, stdout nur Nutzdaten (für Skripte)",
    )


def _add_verbose_arg(subparser) -> None:
    """Add the shared ``--verbose`` flag (phase log to stderr)."""
    subparser.add_argument(
        "--verbose",
        action="store_true",
        help="Ausführlich: Zeit-Phasen nach stderr (für Diagnose)",
    )


EXAMPLES = """Beispiele:
  ptt host                    Tunnel öffnen (PIN steht im Banner)
  ptt host --name wohnzimmer  Host mit Anzeigenamen öffnen
  ptt connect                 Host im WLAN suchen und verbinden
  ptt connect 192.168.1.42    Direkt per IP verbinden
  ptt doctor                  Umgebung prüfen (bei Problemen zuerst)
  ptt update                  PTT aktualisieren (mit Vorschau)
  ptt update --yes            Ohne Rückfrage aktualisieren
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ptt",
        description="PTT - Private Terminal Tunnel: Terminal im Heimnetz "
        "freigeben und nutzen.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    host = sub.add_parser(
        "host",
        help="Tunnel öffnen: dieses Gerät freigeben.",
        description="Tunnel auf diesem Gerät öffnen und Sitzungen annehmen.",
    )
    host.add_argument(
        "--bind", default="0.0.0.0", help="Listen-Adresse (Default: 0.0.0.0)"
    )
    _add_port_arg(host, "Listen-Port")
    _add_verbose_arg(host)
    host.add_argument(
        "--shell",
        default=None,
        help="Shell-Befehl (Default: auto aus $SHELL bzw. COMSPEC)",
    )
    host.add_argument(
        "--token", default=None, help="Eigenes Token (Default: zufällig)"
    )
    host.add_argument(
        "--token-file",
        default=None,
        help="Token aus Datei lesen (Alternative zu PTT_TOKEN)",
    )
    host.add_argument(
        "--cert-dir", default=None, help="Zertifikat-Verzeichnis (Default: ~/.ptt)"
    )
    host.add_argument(
        "--once",
        action="store_true",
        help="Nach einer Sitzung beenden (Default: weiter lauschen)",
    )
    _add_color_arg(host)
    host.add_argument(
        "--name", default=None, help="Anzeigename im WLAN (Default: Rechnername)"
    )
    host.add_argument(
        "--pin", default=None, help="Feste PIN (Default: zufällig, rotiert)"
    )
    host.add_argument(
        "--idle-timeout",
        type=float,
        default=0.0,
        help="Sitzung bei Inaktivität beenden (Minuten, 0 = aus)",
    )
    host.add_argument(
        "--max-session",
        type=float,
        default=0.0,
        help="Maximale Sitzungsdauer (Minuten, 0 = aus)",
    )
    host.add_argument(
        "--max-sessions",
        type=int,
        default=1,
        help="Max. parallele Sitzungen (0 = unbegrenzt, ohne Wirkung mit --once)",
    )
    host.add_argument(
        "--transfer-dir",
        default=None,
        help="Zielverzeichnis für Datei-Uploads (Default: Arbeitsverzeichnis)",
    )
    host.add_argument(
        "--max-transfer-size",
        type=parse_size,
        default=0,
        metavar="GRÖSSE",
        help="Max. Dateigröße für Transfer, z. B. 100M (0 = unbegrenzt)",
    )
    host.add_argument(
        "--no-discover",
        dest="discover",
        action="store_false",
        help="Nicht im WLAN ankündigen (nur direkt verbinden)",
    )

    connect = sub.add_parser(
        "connect",
        help="Mit offenem Tunnel verbinden.",
        description="Mit einem offenen Tunnel verbinden: ohne Adresse im WLAN "
        "suchen und aus der Liste wählen, mit Adresse direkt verbinden.",
    )
    connect.add_argument(
        "host",
        nargs="?",
        default=None,
        help="Adresse des PTT-Hosts (leer = im WLAN suchen, Env: PTT_HOST)",
    )
    _add_port_arg(connect, "Port des PTT-Hosts")
    _add_color_arg(connect)
    _add_quiet_arg(connect)
    _add_verbose_arg(connect)
    connect.add_argument(
        "--token", default=None, help="Token (Default: interaktiv abfragen)"
    )
    connect.add_argument(
        "--token-file",
        default=None,
        help="Token aus Datei lesen (Alternative zu PTT_TOKEN)",
    )
    connect.add_argument(
        "--retry",
        type=int,
        default=0,
        help="Wiederholungen bei Verbindungsfehler (0 = keine)",
    )
    connect.add_argument(
        "--retry-delay",
        type=float,
        default=2.0,
        help="Startwert der Wartezeit zwischen Versuchen in s (verdoppelt sich)",
    )
    connect.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Gesamt-Zeitlimit in s (0 = aus, Env: PTT_TIMEOUT)",
    )
    connect.add_argument(
        "--put",
        action="append",
        default=None,
        metavar="DATEI[:NAME]",
        help="Datei hochladen statt Shell (wiederholbar, erst alle --put)",
    )
    connect.add_argument(
        "--get",
        action="append",
        default=None,
        metavar="REMOTE[:LOKAL]",
        help="Datei herunterladen statt Shell (wiederholbar, nach --put)",
    )
    connect.add_argument(
        "--fresh",
        action="store_true",
        help="Transfer von vorn beginnen statt fortzusetzen",
    )
    execute = sub.add_parser(
        "exec",
        help="Einen Befehl auf dem Host ausführen (für Skripte).",
        description="Einen Befehl auf dem Host ausführen: ohne TTY, "
        "Remote-Ausgabe nach stdout, Remote-Exit-Code als Exit-Code. "
        "Der Befehl läuft direkt ohne Shell (`sh -c` ggf. explizit); "
        "Argumente mit Bindestrich ggf. nach `--` angeben.",
    )
    execute.add_argument(
        "host",
        help="Adresse des PTT-Hosts",
    )
    _add_port_arg(execute, "Port des PTT-Hosts")
    _add_color_arg(execute)
    _add_quiet_arg(execute)
    _add_verbose_arg(execute)
    execute.add_argument(
        "--token", default=None, help="Token (Default: interaktiv abfragen)"
    )
    execute.add_argument(
        "--token-file",
        default=None,
        help="Token aus Datei lesen (Alternative zu PTT_TOKEN)",
    )
    execute.add_argument(
        "--retry",
        type=int,
        default=0,
        help="Wiederholungen bei Verbindungsfehler (0 = keine)",
    )
    execute.add_argument(
        "--retry-delay",
        type=float,
        default=2.0,
        help="Startwert der Wartezeit zwischen Versuchen in s (verdoppelt sich)",
    )
    execute.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Gesamt-Zeitlimit in s (0 = aus, Env: PTT_TIMEOUT)",
    )
    execute.add_argument(
        "argv",
        nargs="+",
        metavar="BEFEHL",
        help="Befehl und Argumente (läuft ohne Shell auf dem Host)",
    )
    # Named for future doctor options (see 0.10.x).
    doctor = sub.add_parser(
        "doctor",
        help="Umgebung prüfen (bei Problemen zuerst).",
        description="Prüft die PTT-Umgebung: je Prüfung eine Zeile "
        "(Exit 0, bei FAIL 1).",
    )
    doctor.add_argument(
        "--json",
        action="store_true",
        help="Als JSON ausgeben (für Skripte)",
    )
    doctor.add_argument(
        "--fix",
        action="store_true",
        help="Sichere Befunde reparieren (Dateirechte, immer lesbar)",
    )
    doctor.add_argument(
        "--dry-run",
        action="store_true",
        help="Mit --fix: nur Vorschau, nichts ändern",
    )
    doctor.add_argument(
        "--self-test",
        action="store_true",
        help="Ende-zu-Ende-Selbsttest: "
        "Test-Zertifikat, exec, Upload, Download",
    )
    doctor.add_argument(
        "--list",
        action="store_true",
        help="Alle Prüfungen mit ID auflisten (s. --check)",
    )
    doctor.add_argument(
        "--check",
        metavar="ID",
        help="Nur diese Prüfung(en) ausführen, "
        "Komma-getrennt (s. --list)",
    )
    doctor.add_argument(
        "--report",
        nargs="?",
        const="-",
        metavar="DATEI",
        help="Redigierter Diagnosebericht als Markdown "
        "(stdout, oder in DATEI schreiben)",
    )
    scan = sub.add_parser(
        "scan",
        help="Hosts im WLAN suchen (ohne zu verbinden).",
        description="Sucht per LAN-Broadcast nach PTT-Hosts und listet sie "
        "auf, ohne zu verbinden.",
    )
    _add_color_arg(scan)
    scan.add_argument(
        "--json",
        action="store_true",
        help="Als JSON ausgeben (für Skripte)",
    )
    update = sub.add_parser(
        "update",
        help="PTT aktualisieren (git pull oder pip).",
        description="PTT aktualisieren: zeigt erst die Änderung, fragt um "
        "Bestätigung (außer --yes).",
    )
    update.add_argument(
        "--yes",
        action="store_true",
        help="Ohne Rückfrage aktualisieren (für Skripte)",
    )
    reset = sub.add_parser(
        "reset",
        help="Eigene PTT-Daten löschen (Zertifikat, Hosts).",
        description="Löscht Zertifikat und gespeicherte Hosts aus ~/.ptt: "
        "zeigt erst die Vorschau, fragt um Bestätigung (außer --yes).",
    )
    reset.add_argument(
        "--yes",
        action="store_true",
        help="Ohne Rückfrage löschen (für Skripte)",
    )
    reset.add_argument(
        "--dry-run",
        action="store_true",
        help="Nur Vorschau, nichts löschen",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "host":
        if args.idle_timeout < 0:
            parser.error("--idle-timeout darf nicht negativ sein")
        if args.max_session < 0:
            parser.error("--max-session darf nicht negativ sein")
        if args.max_sessions < 0:
            parser.error("--max-sessions darf nicht negativ sein")
        port = _resolve_opt(
            args.port, "PTT_PORT", _validate_port, DEFAULT_PORT, parser
        )
        try:
            token = _resolve_token(args.token, args.token_file)
            _warn_short_token(token)
            run_host(
                bind=args.bind,
                port=port,
                shell=args.shell or default_shell(),
                token=token,
                cert_dir=args.cert_dir or default_cert_dir(),
                once=args.once,
                color_mode=args.color,
                name=args.name,
                pin=args.pin,
                discover=args.discover,
                idle_timeout=args.idle_timeout,
                max_session=args.max_session,
                max_sessions=args.max_sessions,
                transfer_dir=args.transfer_dir,
                max_transfer_size=args.max_transfer_size,
                verbose=args.verbose,
            )
        except ValueError as exc:
            parser.error(str(exc))
        return 0
    if args.command == "doctor":
        if args.dry_run and not args.fix:
            parser.error("--dry-run braucht --fix")
        if args.fix and args.self_test:
            parser.error("--fix und --self-test schließen sich aus")
        if args.list and (
            args.fix or args.self_test or args.check
            or args.report is not None
        ):
            parser.error("--list ist nicht kombinierbar")
        if args.check and (args.fix or args.self_test):
            parser.error(
                "--check ist nicht mit --fix/--self-test kombinierbar"
            )
        if args.report is not None and (
            args.fix or args.self_test or args.check or args.json
        ):
            parser.error("--report ist nicht kombinierbar")
        if args.list:
            return list_checks(as_json=args.json)
        if args.report is not None:
            return run_report(path=args.report)
        if args.fix:
            return run_fix(dry_run=args.dry_run)
        only = None
        if args.check:
            only = _parse_check_ids(parser, args.check)
        return run_doctor(
            as_json=args.json, self_test=args.self_test, only=only
        )
    if args.command == "scan":
        return run_scan(color_mode=args.color, as_json=args.json)
    if args.command == "update":
        return run_update(assume_yes=args.yes)
    if args.command == "reset":
        return run_reset(assume_yes=args.yes, dry_run=args.dry_run)
    if args.retry < 0:
        parser.error("--retry darf nicht negativ sein")
    if args.retry_delay < 0:
        parser.error("--retry-delay darf nicht negativ sein")
    port = _resolve_opt(
        args.port, "PTT_PORT", _validate_port, DEFAULT_PORT, parser
    )
    timeout = _resolve_opt(
        args.timeout, "PTT_TIMEOUT", _parse_timeout, 0, parser
    )
    if timeout < 0:
        parser.error("--timeout darf nicht negativ sein")
    if args.command == "exec":
        # Note: PTT_HOST is connect-only; a positional HOST plus a
        # positional BEFEHL leaves no unambiguous room for it here.
        if not args.argv:
            parser.error("exec braucht einen BEFEHL")
        try:
            token = _resolve_token(args.token, args.token_file)
        except ValueError as exc:
            parser.error(str(exc))
        return run_exec(
            args.host, port, token, args.color,
            retry=args.retry, retry_delay=args.retry_delay,
            argv=args.argv, timeout=timeout, quiet=args.quiet,
            verbose=args.verbose,
        )
    if args.fresh and args.put is None and args.get is None:
        parser.error("--fresh braucht --put oder --get")
    host = _resolve_opt(args.host, "PTT_HOST", None, None, parser)
    try:
        token = _resolve_token(args.token, args.token_file)
    except ValueError as exc:
        parser.error(str(exc))
    return run_client(
        host, port, token, args.color,
        retry=args.retry, retry_delay=args.retry_delay,
        put=args.put, get=args.get, fresh=args.fresh,
        timeout=timeout, quiet=args.quiet, verbose=args.verbose,
    )
