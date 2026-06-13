"""Table rendering helpers used by the legacy report renderer facade."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from r2morph.reporting.report_rendering_primitives import create_table


def render_mismatch_table(
    console: Console,
    mismatch_rows: list[tuple[str, int | None, int | None, list[str]]],
) -> None:
    """Render a table of observable mismatches."""
    table = create_table(
        "Observable Mismatches by Pass",
        [
            ("Pass", "cyan"),
            ("Count", "red"),
            ("Observables", "yellow"),
        ],
    )

    for pass_name, start_addr, end_addr, observables in mismatch_rows:
        table.add_row(
            pass_name,
            str(len(observables)),
            ", ".join(observables[:5]) + ("..." if len(observables) > 5 else ""),
        )

    console.print(table)


def render_pass_evidence_table(
    console: Console,
    pass_results: dict[str, Any],
) -> None:
    """Render a table of pass evidence summaries."""
    table = create_table(
        "Pass Evidence Summary",
        [
            ("Pass", "cyan"),
            ("Changed Regions", "blue"),
            ("Structural Issues", "red"),
            ("Symbolic Mismatches", "red"),
            ("Status", "yellow"),
        ],
    )

    for pass_name, result in pass_results.items():
        evidence = result.get("evidence_summary", {})
        table.add_row(
            pass_name,
            str(evidence.get("changed_region_count", 0)),
            str(evidence.get("structural_issue_count", 0)),
            str(evidence.get("symbolic_binary_mismatched_regions", 0)),
            result.get("status", "unknown"),
        )

    console.print(table)


def render_filtered_summary_table(
    console: Console,
    filtered_summary: dict[str, Any],
    *,
    only_mismatches: bool = False,
    only_failed_gates: bool = False,
) -> None:
    """Render a compact summary table."""
    title = "Filtered Report Summary"
    if only_mismatches:
        title = "Mismatch Summary"
    elif only_failed_gates:
        title = "Failed Gates Summary"

    table = create_table(
        title,
        [
            ("Metric", "cyan"),
            ("Value", "green"),
        ],
    )

    for key, value in filtered_summary.items():
        if isinstance(value, (int, float, str)):
            table.add_row(key.replace("_", " ").title(), str(value))

    console.print(table)
