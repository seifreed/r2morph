"""Pass-oriented table rendering helpers."""

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


def render_only_pass_sections(
    pass_name: str,
    pass_data: dict[str, Any],
    *,
    console: Console | None = None,
) -> None:
    """Render sections for a single pass."""
    c = console or _get_console()

    c.print(f"\n[bold cyan]Pass: {pass_name}[/bold cyan]")

    if pass_data.get("evidence_summary"):
        evidence = pass_data["evidence_summary"]
        table = create_table(
            "Evidence Summary",
            [
                ("Metric", "cyan"),
                ("Value", "green"),
            ],
        )
        table.add_row("Changed Regions", str(evidence.get("changed_region_count", 0)))
        table.add_row("Structural Issues", str(evidence.get("structural_issue_count", 0)))
        table.add_row("Symbolic Mismatches", str(evidence.get("symbolic_binary_mismatched_regions", 0)))
        c.print(table)
