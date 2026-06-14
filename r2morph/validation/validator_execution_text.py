"""Text helpers for binary validation runtime execution."""

from __future__ import annotations

import hashlib


def normalize_output(text: str, normalize_whitespace: bool) -> str:
    """Normalize output text for optional whitespace-insensitive comparison."""
    if not normalize_whitespace:
        return text
    return "\n".join(line.rstrip() for line in text.splitlines()).strip()


def hash_text(text: str) -> str:
    """Return a stable hash for machine-readable runtime reporting."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
