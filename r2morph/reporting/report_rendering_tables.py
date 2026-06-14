"""Table-oriented report rendering helpers."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from r2morph.reporting.report_rendering_primitives import _get_console, create_table
from r2morph.reporting.report_rendering_table_helpers import (
    build_degradation_role_rows,
    build_gate_failure_rows,
    build_mismatch_rows,
    build_symbolic_summary_rows,
)


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
    rows = build_symbolic_summary_rows(
        symbolic_requested=symbolic_requested,
        observable_match=observable_match,
        observable_mismatch=observable_mismatch,
        bounded_only=bounded_only,
        without_coverage=without_coverage,
    )
    if not rows:
        return

    c = console or _get_console()
    table = create_table(
        "Symbolic Validation Summary",
        [
            ("Metric", "cyan"),
            ("Count", "green"),
        ],
    )

    for label, value in rows:
        table.add_row(label, value)

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

    for pass_name, failure_count, strictest in build_gate_failure_rows(gate_failure_priority):
        table.add_row(pass_name, failure_count, strictest)

    c.print(table)


def render_degradation_sections(
    degradation_summary: dict[str, Any],
    *,
    console: Console | None = None,
) -> None:
    """Render validation mode degradation summary."""
    c = console or _get_console()

    rows = build_degradation_role_rows(degradation_summary)
    if not rows:
        return

    table = create_table(
        "Validation Mode Degradation",
        [
            ("Role", "cyan"),
            ("Count", "yellow"),
        ],
    )

    for role, count in rows:
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

    for pass_name, mismatch_count, region_count in build_mismatch_rows(mismatch_rows):
        table.add_row(pass_name, mismatch_count, region_count)

    c.print(table)
