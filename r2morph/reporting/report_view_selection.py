"""Pure selection helpers for reporting views."""

from __future__ import annotations

from typing import Any


def _first_available(*sources: Any) -> Any:
    """Return the first truthy value from sources, or the last one."""
    for source in sources:
        if source:
            return source
    return sources[-1] if sources else None
