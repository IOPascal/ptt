"""PTT self-update: pull the latest version from git or reinstall via pip."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

REPO_URL = "https://github.com/IOPascal/ptt"


def package_source_dir() -> str:
    """Directory containing the running ``ptt`` package (repo root candidate)."""
    package_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(package_dir)


def git_root(path: str) -> str | None:
    """Git toplevel for ``path``, or None if git is missing/not a repo."""
    if shutil.which("git") is None:
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", path, "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _short_head(repo: str) -> str:
    proc = subprocess.run(
        ["git", "-C", repo, "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "?"


def _update_via_git(repo: str) -> int:
    print(f"[*] Aktualisiere aus Git-Repo: {repo}")
    before = _short_head(repo)
    proc = subprocess.run(["git", "-C", repo, "pull", "--ff-only"])
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


def _update_via_pip() -> int:
    print("[*] Keine Git-Installation, aktualisiere via pip ...")
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--upgrade", f"git+{REPO_URL}"]
    )
    if proc.returncode != 0:
        print("[-] pip-Update fehlgeschlagen.")
        return 1
    print("[+] Update via pip abgeschlossen.")
    return 0


def run_update(source_dir: str | None = None) -> int:
    """Update the tool. Returns the process exit code."""
    if shutil.which("git") is None:
        print("[-] 'git' nicht gefunden. Bitte git installieren und erneut versuchen.")
        return 1
    repo = git_root(source_dir or package_source_dir())
    if repo is not None:
        return _update_via_git(repo)
    return _update_via_pip()
