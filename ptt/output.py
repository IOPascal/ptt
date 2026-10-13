"""Terminal output helpers: colors and status markers."""
from __future__ import annotations

import os
import sys
import time

ANSI = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "cyan": "\x1b[36m",
    "bright_green": "\x1b[92m",
}

#: Shared client message when --timeout expires (shell/exec/transfer).
TIMEOUT_MESSAGE = "Zeitlimit überschritten."

#: Exit code for an expired --timeout (and remote idle kills), like GNU timeout(1).
TIMEOUT_EXIT_CODE = 124


def log_phase(verbose: bool, start: float, message: str) -> None:
    """One timestamped phase line to stderr (only when ``verbose``).

    ``start`` is a ``time.monotonic()`` baseline; the line shows the
    elapsed seconds (``[+0.12s] ...``) for --verbose diagnosis.
    """
    if not verbose:
        return
    elapsed = time.monotonic() - start
    print(f"[+{elapsed:0.2f}s] {message}", file=sys.stderr, flush=True)


def use_color(mode: str) -> bool:
    """Whether to emit ANSI colors (mode: auto/always/never)."""
    if mode == "always":
        return True
    if mode == "never":
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def paint(color: bool, code: str, text: str) -> str:
    if not color or not code:
        return text
    return f"{code}{text}{ANSI['reset']}"


def ok(color: bool) -> str:
    """Success marker (``[+]``), painted when ``color`` is true."""
    return paint(color, ANSI["green"], "[+]")


def err(color: bool) -> str:
    """Error marker (``[-]``), painted when ``color`` is true."""
    return paint(color, ANSI["red"], "[-]")


def info(color: bool) -> str:
    """Info marker (``[*]``), painted when ``color`` is true."""
    return paint(color, ANSI["cyan"], "[*]")


def format_bytes(count: int) -> str:
    """Human-readable byte count (``33 B``, ``1.2 KB``)."""
    if count < 1024:
        return f"{count} B"
    if count < 1024**2:
        return f"{count / 1024:.1f} KB"
    if count < 1024**3:
        return f"{count / 1024**2:.1f} MB"
    return f"{count / 1024**3:.1f} GB"


def format_duration(seconds: float) -> str:
    """Human-readable duration (``12 s``, ``3 min``, ``1 h 5 min``)."""
    total = int(seconds)
    if total < 60:
        return f"{total} s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        if secs == 0:
            return f"{minutes} min"
        return f"{minutes} min {secs} s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min"
