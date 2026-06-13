"""Report renderer orchestration helpers."""

from __future__ import annotations

from typing import Any


def render_report(
    console_renderer: Any,
    payload: dict[str, Any],
    *,
    summary_only: bool = False,
    only_mismatches: bool = False,
    only_failed_gates: bool = False,
) -> None:
    """Render a complete report payload."""
    summary = payload.get("summary", {})

    if only_failed_gates:
        console_renderer.render_gate_failure_summary(
            payload.get("gate_failures", {}),
            payload.get("gate_failure_priority", []),
        )
        return

    if only_mismatches:
        _render_mismatches_only(console_renderer, payload, summary)
        return

    _render_full_report(console_renderer, payload, summary, summary_only)


def _render_mismatches_only(
    console_renderer: Any,
    payload: dict[str, Any],
    summary: dict[str, Any],
) -> None:
    """Render only the mismatches section of a report."""
    symbolic_overview = summary.get("symbolic_overview", {})
    mismatch_rows = []

    for mutation in payload.get("mutations", []):
        metadata = mutation.get("metadata", {})
        if not metadata.get("symbolic_observable_check_performed"):
            continue
        if metadata.get("symbolic_observable_equivalent", False):
            continue
        pass_name = mutation.get("pass_name", "unknown")
        start_addr = mutation.get("start_address")
        end_addr = mutation.get("end_address")
        observables = list(metadata.get("symbolic_observable_mismatches", []))
        mismatch_rows.append((pass_name, start_addr, end_addr, observables))

    console_renderer.render_symbolic_sections(
        symbolic_requested=int(symbolic_overview.get("symbolic_requested", 0)),
        observable_match=int(symbolic_overview.get("observable_match", 0)),
        observable_mismatch=int(symbolic_overview.get("observable_mismatch", 0)),
        bounded_only=int(symbolic_overview.get("bounded_only", 0)),
        observable_not_run=int(symbolic_overview.get("without_coverage", 0)),
        summary=summary,
        pass_results={},
        by_pass={},
        mismatch_rows=mismatch_rows,
    )


def _render_full_report(
    console_renderer: Any,
    payload: dict[str, Any],
    summary: dict[str, Any],
    summary_only: bool,
) -> None:
    """Render the full report with all sections."""
    pass_results = payload.get("pass_results", {})

    console_renderer.render_pass_evidence_table(pass_results)

    if payload.get("gate_failures"):
        console_renderer.render_gate_failure_summary(
            payload.get("gate_failures", {}),
            payload.get("gate_failure_priority", []),
        )

    if summary.get("degradation_roles"):
        console_renderer.render_degradation_summary(
            payload.get("validation_policy", {}),
            summary.get("degradation_roles", {}),
        )

    if not summary_only:
        _render_mismatches_only(console_renderer, payload, summary)
