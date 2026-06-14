"""Table rendering helpers used by the legacy report renderer facade."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from r2morph.reporting.report_rendering_primitives import create_table
from r2morph.reporting.report_rendering_table_helpers import (
    build_filtered_summary_rows,
    build_mismatch_observable_rows,
    build_pass_evidence_rows,
)


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

    for pass_name, count, observables in build_mismatch_observable_rows(mismatch_rows):
        table.add_row(pass_name, count, observables)

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

    for pass_name, changed_regions, structural_issues, symbolic_mismatches, status in build_pass_evidence_rows(
        pass_results
    ):
        table.add_row(pass_name, changed_regions, structural_issues, symbolic_mismatches, status)

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

    for label, value in build_filtered_summary_rows(filtered_summary):
        table.add_row(label, value)

    console.print(table)
