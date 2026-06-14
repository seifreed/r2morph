"""Compatibility helpers for report context dataclasses."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_context_mapping import (
    report_context_contains,
    report_context_get,
    report_context_getitem,
    report_context_items,
    report_context_iter,
    report_context_keys,
    report_context_to_dict,
    report_context_values,
)


class ReportViewsMappingMixin:
    """Dict-like compatibility for ReportViews."""

    def __getitem__(self, key: str) -> Any:
        return report_context_getitem(self, key)

    def __contains__(self, key: str) -> bool:
        return report_context_contains(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-compatible .get() for backward compatibility."""
        return report_context_get(self, key, default)

    def keys(self) -> list[str]:
        """Return field names, enabling dict(report_views)."""
        return report_context_keys(self)

    def values(self) -> list[Any]:
        """Return field values."""
        return report_context_values(self)

    def items(self) -> list[tuple[str, Any]]:
        """Return (name, value) pairs."""
        return report_context_items(self)

    def __iter__(self):
        """Iterate over field names so dict(obj) works."""
        return report_context_iter(self)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for backward compatibility."""
        return report_context_to_dict(self)
