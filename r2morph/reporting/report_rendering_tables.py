"""Table-oriented report rendering helpers."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from r2morph.reporting.report_rendering_primitives import _get_console, create_table


def render_symbolic_sections(
    symbolic_requested: int,
    observable_match: int,
    observable_mismatch: int,
    bounded_only: int,
    without_coverage: int,
    *,
    console: Console | None = None,
) -> None:
    """Render symbolic validation summary."""
    if symbolic_requested == 0:
        return

    c = console or _get_console()
    table = create_table(
        "Symbolic Validation Summary",
        [
            ("Metric", "cyan"),
            ("Count", "green"),
        ],
    )

    table.add_row("Symbolic Regions Checked", str(symbolic_requested))
    table.add_row("Observable Match", str(observable_match))
    table.add_row("Observable Mismatch", str(observable_mismatch))
    table.add_row("Bounded Only", str(bounded_only))
    table.add_row("Without Coverage", str(without_coverage))

    c.print(table)


def render_gate_sections(
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """Render gate failure summary."""
    c = console or _get_console()

    if not gate_failure_summary.get("require_pass_severity_failure_count", 0):
        c.print("[green]All gate checks passed[/green]")
        return

    table = create_table(
        "Gate Failures",
        [
            ("Pass", "cyan"),
            ("Failure Count", "red"),
            ("Strictest Severity", "yellow"),
        ],
    )

    for row in gate_failure_priority:
        table.add_row(
            row.get("pass_name", "unknown"),
            str(row.get("failure_count", 0)),
            row.get("strictest_expected_severity", "unknown"),
        )

    c.print(table)


def render_degradation_sections(
    degradation_summary: dict[str, Any],
    *,
    console: Console | None = None,
) -> None:
    """Render validation mode degradation summary."""
    c = console or _get_console()

    if not degradation_summary.get("degraded_validation"):
        return

    table = create_table(
        "Validation Mode Degradation",
        [
            ("Role", "cyan"),
            ("Count", "yellow"),
        ],
    )

    for role, count in degradation_summary.get("roles", {}).items():
        table.add_row(role, str(count))

    c.print(table)


def render_only_mismatches_sections(
    mismatch_rows: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """Render only-mismatches report sections."""
    if not mismatch_rows:
        return

    c = console or _get_console()
    table = create_table(
        "Observable Mismatches by Pass",
        [
            ("Pass", "cyan"),
            ("Mismatch Count", "red"),
            ("Regions Checked", "blue"),
        ],
    )

    for row in mismatch_rows:
        table.add_row(
            row.get("pass_name", "unknown"),
            str(row.get("mismatch_count", 0)),
            str(row.get("region_count", 0)),
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
