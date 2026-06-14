"""General summary table rendering helpers."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from r2morph.reporting.report_rendering_primitives import _get_console, create_table
from r2morph.reporting.report_rendering_summary_table_helpers import (
    build_summary_rows,
    build_validation_context_rows,
)


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

    for label, value in build_summary_rows(summary):
        table.add_row(label, value)

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

    for pass_name, mode, degraded in build_validation_context_rows(validation_contexts):
        table.add_row(pass_name, mode, degraded)

    c.print(table)
