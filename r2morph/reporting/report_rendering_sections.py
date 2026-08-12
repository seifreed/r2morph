"""Low-level CLI section/table rendering helpers for report output.

These functions use Rich console to render detailed report sections. They form a
leaf layer consumed by report_rendering and report_orchestrator; they depend on
nothing in those modules.
"""

from typing import Any

from r2morph.reporting.report_context import ReportFlowContext
from r2morph.reporting.report_filter_messages import build_report_filter_messages
from r2morph.reporting.report_rendering_primitives import _get_console
from r2morph.reporting.report_rendering_symbolic_tables import (
    _render_coverage_table,
    _render_match_table,
    _render_mismatch_table,
)


def _render_report_filter_messages(ctx: ReportFlowContext) -> None:
    """Render compact filter-resolution/status messages."""
    for message in build_report_filter_messages(ctx.filters, ctx.severity):
        _get_console().print(message)


def _render_only_mismatches_sections(
    ctx: ReportFlowContext,
    mismatch_state: dict[str, Any],
) -> None:
    """Render the textual sections for report --only-mismatches."""
    filtered_mutations = mismatch_state["filtered_mutations"]
    filtered_passes = mismatch_state["filtered_passes"]
    mismatch_counts_by_pass = mismatch_state["mismatch_counts_by_pass"]
    mismatch_observables_by_pass = mismatch_state["mismatch_observables_by_pass"]
    mismatch_pass_context = mismatch_state["mismatch_pass_context"]
    mismatch_degraded_passes = mismatch_state["mismatch_degraded_passes"]
    mismatch_severity_rows = mismatch_state["mismatch_severity_rows"]
    degraded_passes = ctx.validation.degraded_passes
    degraded_validation = ctx.validation.degraded_validation
    _get_console().print(f"[bold]Filtered Mismatch Mutations[/bold]: {len(filtered_mutations)}")
    if degraded_validation:
        _get_console().print(
            "[bold]Mismatch Degradation Context[/bold]: "
            f"requested={ctx.validation.requested_validation_mode or ''}, "
            f"effective={ctx.validation.effective_validation_mode or ''}"
        )
        if mismatch_degraded_passes:
            trigger_names = ", ".join(
                item.get("pass_name", item.get("mutation", "unknown")) for item in mismatch_degraded_passes
            )
            _get_console().print(f"  trigger_passes={trigger_names}")
        elif degraded_passes:
            trigger_names = ", ".join(
                item.get("pass_name", item.get("mutation", "unknown")) for item in degraded_passes
            )
            _get_console().print(f"  trigger_passes={trigger_names}")
    if mismatch_counts_by_pass:
        _get_console().print("[bold]Mismatch Pass Summary[/bold]:")
        for pass_name in filtered_passes:
            count = mismatch_counts_by_pass.get(pass_name, 0)
            role = mismatch_pass_context.get(pass_name, {}).get("role", "unknown")
            observables = mismatch_observables_by_pass.get(pass_name, [])
            observable_fragment = f", observables={','.join(observables)}" if observables else ""
            _get_console().print(
                f"  [cyan]{pass_name}[/cyan]: mismatch_count={count}, role={role}{observable_fragment}"
            )
    if mismatch_severity_rows:
        _get_console().print("[bold]Mismatch Severity Priority[/bold]:")
        for row in mismatch_severity_rows:
            _get_console().print(
                f"  [cyan]{row['pass_name']}[/cyan]: "
                f"severity={row.get('severity', 'unknown')}, "
                f"issue_count={row.get('issue_count', 0)}, "
                f"symbolic_requested={row.get('symbolic_requested', 0)}"
            )
    if filtered_mutations:
        _get_console().print("[bold]Mismatch Addresses[/bold]:")
        for mutation in filtered_mutations:
            pass_name = mutation.get("pass_name", "unknown")
            start = mutation.get("start_address")
            end = mutation.get("end_address")
            if start is None:
                location = "unknown"
            elif end is None or start == end:
                location = f"0x{start:x}"
            else:
                location = f"0x{start:x}-0x{end:x}"
            observables = mutation.get("metadata", {}).get("symbolic_observable_mismatches", [])
            observable_str = ", ".join(observables) if observables else ""
            _get_console().print(f"  [cyan]{pass_name}[/cyan] @ {location}: {observable_str}")


def _render_symbolic_sections(
    symbolic_state: dict[str, Any],
    summary: dict[str, Any],
    pass_results: dict[str, Any],
) -> None:
    """Render symbolic-report sections from persisted summary first, then fall back."""
    if not symbolic_state.get("symbolic_requested", 0):
        return
    console = _get_console()
    coverage_rows = _render_match_table(
        console=console,
        symbolic_state=symbolic_state,
        summary=summary,
        pass_results=pass_results,
    )
    _render_mismatch_table(
        console=console,
        summary=summary,
        by_pass=symbolic_state.get("by_pass", {}),
        coverage_rows=coverage_rows,
    )
    _render_coverage_table(
        console=console,
        summary=summary,
        pass_results=pass_results,
        mismatch_rows=symbolic_state.get("mismatch_rows", []),
    )
