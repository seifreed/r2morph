"""Pure row builders for summary table rendering."""

from __future__ import annotations

from typing import Any


def build_summary_rows(summary: dict[str, Any]) -> list[tuple[str, str]]:
    """Build summary rows in display order."""
    rows: list[tuple[str, str]] = []
    for key, value in summary.items():
        if isinstance(value, dict):
            continue
        if isinstance(value, list):
            continue
        rows.append((key.replace("_", " ").title(), str(value)))
    return rows


def build_validation_context_rows(
    validation_contexts: list[dict[str, Any]],
) -> list[tuple[str, str, str]]:
    """Build validation context rows in display order."""
    return [
        (
            ctx.get("pass_name", "unknown"),
            ctx.get("validation_mode", "unknown"),
            "Yes" if ctx.get("degraded_execution") else "No",
        )
        for ctx in validation_contexts
    ]
