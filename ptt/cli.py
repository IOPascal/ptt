"""PTT command line interface."""
from __future__ import annotations

import argparse

from . import __version__
from .cert import default_cert_dir
from .client import run_client
from .host import DEFAULT_PORT, default_shell, run_host
from .update import run_update


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ptt",
        description="PTT - Private Terminal Tunnel: Terminal im Heimnetz "
        "freigeben und nutzen.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    host = sub.add_parser("host", help="Tunnel öffnen: dieses Gerät freigeben.")
    host.add_argument("--bind", default="0.0.0.0", help="Listen-Adresse")
    host.add_argument("--port", type=int, default=DEFAULT_PORT, help="Listen-Port")
    host.add_argument("--shell", default=None, help="Shell (Default: auto)")
    host.add_argument(
        "--token", default=None, help="Eigenes Token (Default: zufällig)"
    )
    host.add_argument("--cert-dir", default=None, help="Zertifikat-Verzeichnis")
    host.add_argument(
        "--once",
        action="store_true",
        help="Nach einer Sitzung beenden (Default: weiter lauschen)",
    )
    host.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Farbige Ausgabe (Default: auto)",
    )
    host.add_argument(
        "--name", default=None, help="Anzeigename im WLAN (Default: Rechnername)"
    )
    host.add_argument(
        "--pin", default=None, help="Feste PIN (Default: zufällig, rotiert)"
    )
    host.add_argument(
        "--no-discover",
        dest="discover",
        action="store_false",
        help="Nicht im WLAN ankündigen (nur direkt verbinden)",
    )

    connect = sub.add_parser("connect", help="Mit offenem Tunnel verbinden.")
    connect.add_argument(
        "host",
        nargs="?",
        default=None,
        help="Adresse des PTT-Hosts (leer = im WLAN suchen)",
    )
    connect.add_argument("--port", type=int, default=DEFAULT_PORT)
    connect.add_argument(
        "--token", default=None, help="Token (Default: interaktiv abfragen)"
    )
    sub.add_parser("update", help="PTT aktualisieren (git pull oder pip).")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "host":
        try:
            run_host(
                bind=args.bind,
                port=args.port,
                shell=args.shell or default_shell(),
                token=args.token,
                cert_dir=args.cert_dir or default_cert_dir(),
                once=args.once,
                color_mode=args.color,
                name=args.name,
                pin=args.pin,
                discover=args.discover,
            )
        except ValueError as exc:
            parser.error(str(exc))
        return 0
    if args.command == "update":
        return run_update()
    return run_client(args.host, args.port, args.token)
