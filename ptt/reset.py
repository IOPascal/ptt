"""PTT reset: delete local identity data in a controlled way."""
from __future__ import annotations

import os

from .cert import CERT_FILE, KEY_FILE, default_cert_dir
from .known_hosts import KNOWN_HOSTS_FILE

#: Managed files, relative to the data dir; nothing else is touched.
MANAGED_FILES = (CERT_FILE, KEY_FILE, KNOWN_HOSTS_FILE)


def _display(path: str) -> str:
    """Shorten paths under $HOME to ``~/...``."""
    home = os.path.expanduser("~")
    if path == home:
        return "~"
    if path.startswith(home + os.sep):
        return "~" + path[len(home):]
    return path


def _confirm_danger(question: str) -> bool:
    """Yes/no prompt, defaulting to no (EOF/Ctrl+C means no)."""
    try:
        answer = input(f"{question} [j/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("j", "ja", "y", "yes")


def _remove(path: str) -> None:
    """Delete one file (thin wrapper so tests can fail it)."""
    os.remove(path)


def run_reset(
    data_dir: str | None = None,
    assume_yes: bool = False,
    dry_run: bool = False,
) -> int:
    """Preview and delete local PTT data; 0 when done, else 1."""
    directory = data_dir or default_cert_dir()
    header = f"[*] PTT-Zurücksetzen ({_display(directory)})"
    if dry_run:
        header += " (Vorschau, nichts geändert)"
    print(header)
    targets = []
    for name in MANAGED_FILES:
        path = os.path.join(directory, name)
        if os.path.islink(path):
            print(f"[*] übersprungen (Symlink): {name}")
        elif os.path.isfile(path):
            print(f"[*] löschen: {name}")
            targets.append(path)
    if not targets:
        print("[*] Nichts zu tun: keine PTT-Daten vorhanden.")
        return 0
    if dry_run:
        noun = "Datei" if len(targets) == 1 else "Dateien"
        print(f"[*] Vorschau: {len(targets)} {noun} würden gelöscht.")
        return 0
    if not assume_yes and not _confirm_danger("Wirklich löschen?"):
        print("[*] Abgebrochen, nichts geändert.")
        return 1
    failed = 0
    for path in targets:
        try:
            _remove(path)
        except OSError as exc:
            print(f"[-] {os.path.basename(path)}: {exc}")
            failed += 1
    if failed:
        return 1
    noun = "Datei" if len(targets) == 1 else "Dateien"
    print(f"[+] Zurückgesetzt: {len(targets)} {noun} gelöscht.")
    print(
        "[*] Neues Zertifikat entsteht beim nächsten `ptt host`; "
        "gespeicherte Hosts müssen neu bestätigt werden."
    )
    return 0
