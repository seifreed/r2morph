"""Report flow execution helpers extracted from report_orchestrator."""

from __future__ import annotations

from r2morph.reporting.filtered_summary_mismatch_payloads import (
    _build_only_mismatches_payload,
    _build_report_filters,
)
from r2morph.reporting.filtered_summary_payloads import _build_general_report_payload
from r2morph.reporting.report_context import ReportFlowContext
from r2morph.reporting.report_flow_rendering import (
    _render_general_flow_sections,
)
from r2morph.reporting.report_output_policy import _finalize_report_output
from r2morph.reporting.report_rendering_sections import _render_only_mismatches_sections
from r2morph.reporting.report_resolver import _resolve_only_mismatches_state


def _execute_general_report_flow(ctx: ReportFlowContext) -> None:
    """Render and emit the general report path."""
    _render_general_flow_sections(ctx)
    filtered_payload = _build_general_report_payload(ctx)
    _finalize_report_output(ctx, filtered_payload)


def _execute_only_mismatches_report_flow(ctx: ReportFlowContext) -> None:
    """Render and emit the `report --only-mismatches` path."""
    summary = ctx.data.summary
    filtered_summary = ctx.data.filtered_summary
    mismatch_state = _resolve_only_mismatches_state(
        summary=summary,
        mutations=ctx.data.mutations,
        filtered_summary=filtered_summary,
        resolved_only_pass=ctx.severity.resolved_only_pass,
        degraded_passes=ctx.validation.degraded_passes,
    )
    _render_only_mismatches_sections(ctx, mismatch_state)
    filtered_payload = _build_only_mismatches_payload(ctx, mismatch_state)
    filtered_payload["report_filters"] = _build_report_filters(ctx.filters, ctx.severity)
    _finalize_report_output(ctx, filtered_payload)
