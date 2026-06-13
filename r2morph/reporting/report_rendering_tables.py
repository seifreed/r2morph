"""Table-oriented report rendering helpers."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from r2morph.reporting.report_rendering_primitives import _get_console, create_table


def render_pass_capabilities(
    capabilities: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """Render pass capabilities table."""
    if not capabilities:
        return

    c = console or _get_console()
    table = create_table(
        "Pass Capabilities",
        [
            ("Pass", "cyan"),
            ("Category", "blue"),
            ("Support", "green"),
        ],
    )

    for cap in capabilities:
        table.add_row(
            cap.get("pass_name", "unknown"),
            cap.get("category", "unknown"),
            cap.get("support", "unknown"),
        )

    c.print(table)


def render_pass_validation_contexts(
    contexts: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """Render pass validation contexts table."""
    if not contexts:
        return

    c = console or _get_console()
    table = create_table(
        "Pass Validation Contexts",
        [
            ("Pass", "cyan"),
            ("Mode", "blue"),
            ("Degraded", "yellow"),
            ("Gate Failures", "red"),
        ],
    )

    for ctx in contexts:
        table.add_row(
            ctx.get("pass_name", "unknown"),
            ctx.get("validation_mode", "unknown"),
            "Yes" if ctx.get("degraded_execution") else "No",
            str(ctx.get("gate_failure_count", 0)),
        )

    c.print(table)


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
