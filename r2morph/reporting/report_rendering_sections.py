"""Low-level CLI section/table rendering helpers for report output.

These functions use Rich console to render detailed report sections. They form a
leaf layer consumed by report_rendering and report_orchestrator; they depend on
nothing in those modules.
"""

from typing import Any

from r2morph.reporting.report_filter_messages import build_report_filter_messages
from r2morph.reporting.report_rendering_flow_sections import (
    _render_degradation_sections as _render_degradation_sections,
)
from r2morph.reporting.report_rendering_flow_sections import (
    _render_gate_sections as _render_gate_sections,
)
from r2morph.reporting.report_rendering_primitives import _get_console
from r2morph.reporting.report_rendering_symbolic_tables import (
    _render_coverage_table as _render_coverage_table,
)
from r2morph.reporting.report_rendering_symbolic_tables import (
    _render_match_table as _render_match_table,
)
from r2morph.reporting.report_rendering_symbolic_tables import (
    _render_mismatch_table as _render_mismatch_table,
)


def _render_report_filter_messages(
    *,
    only_pass: str | None,
    resolved_only_pass: str | None,
    only_pass_failure: str | None,
    resolved_only_pass_failure: str | None,
    only_risky_passes: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    selected_risk_pass_names: set[str],
) -> None:
    """Render compact filter-resolution/status messages."""
    for message in build_report_filter_messages(
        only_pass=only_pass,
        resolved_only_pass=resolved_only_pass,
        only_pass_failure=only_pass_failure,
        resolved_only_pass_failure=resolved_only_pass_failure,
        only_risky_passes=only_risky_passes,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        selected_risk_pass_names=selected_risk_pass_names,
    ):
        _get_console().print(message)


def _render_only_mismatches_sections(
    *,
    filtered_mutations: list[dict[str, Any]],
    filtered_passes: list[str],
    mismatch_counts_by_pass: dict[str, int],
    mismatch_observables_by_pass: dict[str, list[str]],
    mismatch_pass_context: dict[str, Any],
    mismatch_degraded_passes: list[dict[str, Any]],
    degraded_passes: list[dict[str, Any]],
    degraded_validation: bool,
    requested_validation_mode: str,
    effective_validation_mode: str,
    mismatch_severity_rows: list[dict[str, Any]],
) -> None:
    """Render the textual sections for report --only-mismatches."""
    _get_console().print(f"[bold]Filtered Mismatch Mutations[/bold]: {len(filtered_mutations)}")
    if degraded_validation:
        _get_console().print(
            "[bold]Mismatch Degradation Context[/bold]: "
            f"requested={requested_validation_mode}, effective={effective_validation_mode}"
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
    *,
    symbolic_requested: int,
    observable_match: int,
    observable_mismatch: int,
    bounded_only: int,
    observable_not_run: int,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    by_pass: dict[str, dict[str, int]],
    mismatch_rows: list[tuple[str, int | None, int | None, list[str]]],
) -> None:
    """Render symbolic-report sections from persisted summary first, then fall back."""
    if not symbolic_requested:
        return
    console = _get_console()
    coverage_rows = _render_match_table(
        console=console,
        observable_match=observable_match,
        observable_mismatch=observable_mismatch,
        bounded_only=bounded_only,
        observable_not_run=observable_not_run,
        summary=summary,
        pass_results=pass_results,
        by_pass=by_pass,
    )
    _render_mismatch_table(
        console=console,
        summary=summary,
        by_pass=by_pass,
        coverage_rows=coverage_rows,
    )
    _render_coverage_table(
        console=console,
        summary=summary,
        pass_results=pass_results,
        mismatch_rows=mismatch_rows,
    )
