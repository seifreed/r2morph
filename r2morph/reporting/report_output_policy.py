"""Output and exit-policy helpers for filtered reports."""

from __future__ import annotations

from typing import Any

import typer
from rich.console import Console

from r2morph.reporting.report_context import ReportFlowContext
from r2morph.reporting.report_gate_helpers import _gate_failure_result_count
from r2morph.reporting.report_gate_severity_policy import _severity_threshold_met
from r2morph.reporting.report_output_io import emit_report_payload

console = Console()


def _report_view_has_results(
    ctx: ReportFlowContext,
    filtered_summary: dict[str, Any],
) -> bool:
    """Determine whether a filtered report view should count as non-empty."""
    if ctx.filters.only_failed_gates:
        if ctx.filters.only_expected_severity is not None or ctx.severity.resolved_only_pass_failure is not None:
            return int(filtered_summary.get("gate_failures", {}).get("require_pass_severity_failure_count", 0)) > 0
        return _gate_failure_result_count(filtered_summary.get("gate_failures", {})) > 0
    return bool(filtered_summary.get("passes", []))


def _emit_report_payload(
    ctx: ReportFlowContext,
    filtered_payload: dict[str, Any],
) -> None:
    """Write and/or print a filtered report payload."""
    emit_report_payload(
        filtered_payload=filtered_payload,
        output=ctx.output.output,
        summary_only=ctx.output.summary_only,
        console_instance=console,
    )


def _enforce_report_requirements(
    ctx: ReportFlowContext,
    filtered_payload: dict[str, Any],
) -> None:
    """Apply report exit-code policy for empty views or missing severity."""
    filtered_summary = filtered_payload.get("filtered_summary", {})
    severity_ok = _severity_threshold_met(
        filtered_summary.get("symbolic_severity_by_pass", []), ctx.severity.min_severity_rank
    )
    if ctx.output.require_results and (not _report_view_has_results(ctx, filtered_summary) or not severity_ok):
        raise typer.Exit(1)


def _finalize_report_output(
    ctx: ReportFlowContext,
    filtered_payload: dict[str, Any],
) -> None:
    """Emit a filtered report and enforce CLI exit policies."""
    _emit_report_payload(ctx, filtered_payload)
    _enforce_report_requirements(ctx, filtered_payload)
