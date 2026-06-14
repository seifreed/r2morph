"""Pure summary lookup helpers for reporting."""

from __future__ import annotations

from typing import Any


def _summary_first(summary: dict[str, Any], key: str, fallback: Any) -> Any:
    """Return a persisted summary value when present, otherwise the fallback."""
    value = summary.get(key)
    if value is None:
        return fallback
    if isinstance(value, (list, dict)) and not value:
        return fallback
    return value
