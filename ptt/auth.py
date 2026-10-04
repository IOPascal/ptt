"""PIN helpers for simple pairing (6 digits, shown on the host screen)."""
from __future__ import annotations

import secrets


def generate_pin() -> str:
    """Random 6-digit PIN, e.g. ``482913``."""
    return f"{secrets.randbelow(1_000_000):06d}"


def normalize_pin(raw: str) -> str:
    """Keep digits only, so ``482-913`` and ``482 913`` both work."""
    return "".join(ch for ch in raw if ch.isdigit())


def format_pin(pin: str) -> str:
    """Display form: ``482913`` -> ``482-913``."""
    digits = normalize_pin(pin)
    if len(digits) == 6:
        return f"{digits[:3]}-{digits[3:]}"
    return pin
