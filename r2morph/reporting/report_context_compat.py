"""Compatibility helpers for report context dataclasses."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict, fields
from typing import Any


class ReportViewsMappingMixin:
    """Dict-like compatibility for ReportViews."""

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key) and key in {f.name for f in fields(self)}

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-compatible .get() for backward compatibility."""
        try:
            return getattr(self, key)
        except AttributeError:
            return default

    def keys(self) -> list[str]:
        """Return field names, enabling dict(report_views)."""
        return [f.name for f in fields(self)]

    def values(self) -> list[Any]:
        """Return field values."""
        return [getattr(self, f.name) for f in fields(self)]

    def items(self) -> list[tuple[str, Any]]:
        """Return (name, value) pairs."""
        return [(f.name, getattr(self, f.name)) for f in fields(self)]

    def __iter__(self) -> Iterator[str]:
        """Iterate over field names so dict(obj) works."""
        return iter(self.keys())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for backward compatibility."""
        return asdict(self)
