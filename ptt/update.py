"""PTT self-update: pull the latest version from git or reinstall via pip."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

REPO_URL = "https://github.com/IOPascal/ptt"
UPDATE_TIMEOUT = 120  # seconds for pull/pip network operations


def package_source_dir() -> str:
    """Directory containing the running ``ptt`` package (repo root candidate)."""
    package_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(package_dir)


def _run_git(
    repo: str, *args: str, quiet: bool = True, timeout: float | None = None
):
    """Run a git command in ``repo`` (never raises on exit status)."""
    cmd = ["git", "-C", repo, *args]
    if quiet:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        )
    return subprocess.run(cmd, check=False, timeout=timeout)


def _workdir_dirty(repo: str) -> bool:
    """True when the working tree has uncommitted changes."""
    proc = _run_git(repo, "status", "--porcelain")
    return proc.returncode == 0 and bool(proc.stdout.strip())


def git_root(path: str) -> str | None:
    """Git toplevel for ``path``, or None if git is missing/not a repo."""
    if shutil.which("git") is None:
        return None
    try:
        proc = _run_git(path, "rev-parse", "--show-toplevel")
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _short_head(repo: str) -> str:
    proc = _run_git(repo, "rev-parse", "--short", "HEAD")
    return proc.stdout.strip() if proc.returncode == 0 else "?"


def _incoming_commits(repo: str, limit: int = 20) -> list[str]:
    """Fetch and list incoming commit summaries (empty when unavailable)."""
    fetch = _run_git(repo, "fetch", "--quiet", timeout=UPDATE_TIMEOUT)
    if fetch.returncode != 0:
        return []  # e.g. offline: pull below reports the error
    log = _run_git(repo, "log", f"--max-count={limit}", "--oneline", "HEAD..@{u}")
    if log.returncode != 0:
        return []  # e.g. no upstream configured
    return [line for line in log.stdout.splitlines() if line.strip()]


def _confirm(question: str) -> bool:
    """Yes/no prompt, defaulting to yes (EOF/Ctrl+C means no)."""
    try:
        answer = input(f"{question} [J/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("", "j", "ja", "y", "yes")


def _update_via_git(repo: str, assume_yes: bool = False) -> int:
    print(f"[*] Aktualisiere aus Git-Repo: {repo}")
    if _workdir_dirty(repo):
        print("[-] Arbeitsverzeichnis hat lokale Änderungen.")
        print(
            "[-] Nächster Schritt: erst committen oder stashen, "
            "dann erneut versuchen."
        )
        return 1
    try:
        incoming = _incoming_commits(repo)
    except subprocess.TimeoutExpired:
        print("[-] Git-Fetch hat zu lange gedauert (Timeout).")
        return 1
    if incoming:
        print("[*] Neue Commits:")
        for line in incoming:
            print(f"    {line}")
        if not assume_yes and not _confirm("Pull ausführen?"):
            print("[*] Abgebrochen, nichts geändert.")
            return 1
    before = _short_head(repo)
    try:
        proc = _run_git(repo, "pull", "--ff-only", quiet=False, timeout=UPDATE_TIMEOUT)
    except subprocess.TimeoutExpired:
        print("[-] Git-Pull hat zu lange gedauert (Timeout).")
        return 1
    if proc.returncode != 0:
        print(
            "[-] Git-Pull fehlgeschlagen. Bei lokalen Änderungen: "
            "erst committen oder stashen, dann erneut versuchen."
        )
        return 1
    after = _short_head(repo)
    if before == after:
        print(f"[+] Bereits aktuell (Stand: {after}).")
    else:
        print(f"[+] Aktualisiert: {before} -> {after}.")
    return 0


def _update_via_pip(assume_yes: bool = False) -> int:
    print("[*] Keine Git-Installation, aktualisiere via pip ...")
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", f"git+{REPO_URL}"]
    print(f"[*] Befehl: {' '.join(cmd)}")
    if not assume_yes and not _confirm("Ausführen?"):
        print("[*] Abgebrochen, nichts geändert.")
        return 1
    try:
        proc = subprocess.run(cmd, timeout=UPDATE_TIMEOUT)
    except subprocess.TimeoutExpired:
        print("[-] pip-Update hat zu lange gedauert (Timeout).")
        return 1
    if proc.returncode != 0:
        print("[-] pip-Update fehlgeschlagen.")
        return 1
    print("[+] Update via pip abgeschlossen.")
    return 0


def run_update(source_dir: str | None = None, assume_yes: bool = False) -> int:
    """Update the tool. Returns the process exit code."""
    if shutil.which("git") is None:
        print("[-] 'git' nicht gefunden. Bitte git installieren und erneut versuchen.")
        return 1
    repo = git_root(source_dir or package_source_dir())
    if repo is not None:
        return _update_via_git(repo, assume_yes)
    return _update_via_pip(assume_yes)
