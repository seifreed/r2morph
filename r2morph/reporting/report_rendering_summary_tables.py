"""General summary table rendering helpers."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from r2morph.reporting.report_rendering_primitives import _get_console, create_table


def render_summary_table(
    summary: dict[str, Any],
    *,
    console: Console | None = None,
) -> None:
    """Render a generic summary table."""
    c = console or _get_console()

    table = create_table(
        "Report Summary",
        [
            ("Metric", "cyan"),
            ("Value", "green"),
        ],
    )

    for key, value in summary.items():
        if isinstance(value, dict):
            continue
        if isinstance(value, list):
            continue
        table.add_row(key.replace("_", " ").title(), str(value))

    c.print(table)


def render_validation_context_table(
    validation_contexts: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """Render validation context table."""
    if not validation_contexts:
        return

    c = console or _get_console()
    table = create_table(
        "Validation Context",
        [
            ("Pass", "cyan"),
            ("Mode", "blue"),
            ("Degraded", "yellow"),
        ],
    )

    for ctx in validation_contexts:
        table.add_row(
            ctx.get("pass_name", "unknown"),
            ctx.get("validation_mode", "unknown"),
            "Yes" if ctx.get("degraded_execution") else "No",
        )

    c.print(table)
