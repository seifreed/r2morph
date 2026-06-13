"""Text-oriented report rendering helpers."""

from __future__ import annotations

from rich.console import Console

from r2morph.reporting.report_rendering_primitives import _get_console, create_table


def render_report_filter_messages(
    only_pass: str | None,
    resolved_only_pass: str | None,
    only_pass_failure: str | None,
    resolved_only_pass_failure: str | None,
    only_risky_passes: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    *,
    console: Console | None = None,
) -> None:
    """Render filter resolution messages."""
    c = console or _get_console()

    if only_pass is not None and resolved_only_pass != only_pass:
        c.print(f"[bold]Pass Filter Resolution[/bold]: {only_pass} -> {resolved_only_pass}")

    if only_pass_failure is not None and resolved_only_pass_failure != only_pass_failure:
        c.print(f"[bold]Pass Failure Filter Resolution[/bold]: {only_pass_failure} -> {resolved_only_pass_failure}")

    if only_risky_passes:
        c.print("[bold]Filter[/bold]: Showing only passes with symbolic mismatches or structural issues")

    if only_uncovered_passes:
        c.print("[bold]Filter[/bold]: Showing only clean passes without effective symbolic coverage")

    if only_covered_passes:
        c.print("[bold]Filter[/bold]: Showing only clean passes with effective symbolic coverage")

    if only_clean_passes:
        c.print("[bold]Filter[/bold]: Showing only passes with no structural issues and clean symbolic evidence")


def render_mismatch_summary_sections(
    mismatch_counts_by_pass: dict[str, int],
    mismatch_observables_by_pass: dict[str, list[str]],
    *,
    console: Console | None = None,
) -> None:
    """Render mismatch summary sections."""
    c = console or _get_console()

    if not mismatch_counts_by_pass:
        return

    table = create_table(
        "Observable Mismatches Summary",
        [
            ("Pass", "cyan"),
            ("Count", "red"),
            ("Observables", "yellow"),
        ],
    )

    for pass_name, count in sorted(mismatch_counts_by_pass.items(), key=lambda x: -x[1]):
        observables = mismatch_observables_by_pass.get(pass_name, [])[:3]
        obs_str = ", ".join(observables)
        if len(mismatch_observables_by_pass.get(pass_name, [])) > 3:
            obs_str += "..."
        table.add_row(pass_name, str(count), obs_str)

    c.print(table)
