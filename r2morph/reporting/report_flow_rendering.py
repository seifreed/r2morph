"""Rendering helpers for report flow execution."""

from __future__ import annotations

from r2morph.reporting.report_context import ReportFlowContext
from r2morph.reporting.report_rendering_flow_sections import (
    _render_degradation_sections,
    _render_gate_sections,
)
from r2morph.reporting.report_rendering_pass_sections import (
    _render_only_pass_sections,
    _render_pass_capabilities,
    _render_pass_validation_contexts,
)
from r2morph.reporting.report_rendering_sections import (
    _render_symbolic_sections,
)
from r2morph.reporting.report_resolver import _resolve_only_pass_view


def _render_general_flow_sections(ctx: ReportFlowContext) -> None:
    """Render the general report sections before output emission."""
    _render_general_report_sections(ctx)
    _render_general_only_pass_sections(ctx)
    symbolic_state = ctx.data.symbolic_state
    _render_symbolic_sections(symbolic_state, ctx.data.filtered_summary, ctx.data.pass_results)


def _render_general_report_sections(ctx: ReportFlowContext) -> None:
    """Render the general non-mismatch report sections."""
    filtered_summary = ctx.data.filtered_summary
    degraded_passes = ctx.validation.degraded_passes
    degraded_severity_rows = [
        row
        for row in filtered_summary["symbolic_severity_by_pass"]
        if row.get("pass_name") in {item.get("pass_name", item.get("mutation", "unknown")) for item in degraded_passes}
    ]
    _render_degradation_sections(
        ctx.validation,
        degraded_severity_rows,
    )
    if ctx.gates.gate_evaluation:
        _render_gate_sections(
            ctx.gates,
            filtered_summary.get("gate_failure_priority", []) or ctx.gates.gate_failure_priority,
        )
    _render_pass_capabilities(filtered_summary=filtered_summary)
    if ctx.data.pass_results:
        _render_pass_validation_contexts(
            filtered_summary=filtered_summary,
            pass_results=ctx.data.pass_results,
            degraded_passes=degraded_passes,
        )


def _render_general_only_pass_sections(ctx: ReportFlowContext) -> None:
    """Render single-pass sections for the general report flow."""
    resolved_only_pass = ctx.severity.resolved_only_pass
    if not resolved_only_pass:
        return
    summary = ctx.data.summary
    filtered_summary = ctx.data.filtered_summary
    (
        pass_symbolic_summary,
        pass_evidence,
        pass_validation_context,
        pass_region_evidence,
    ) = _resolve_only_pass_view(
        summary=summary,
        filtered_summary=filtered_summary,
        pass_results=ctx.data.pass_results,
        pass_name=resolved_only_pass,
    )
    capability_map = dict(summary.get("pass_capability_summary_map", {}) or {})
    capability_row = filtered_summary.get("pass_capability_summary", {})
    if isinstance(capability_row, list):
        capability_row = next(
            (row for row in capability_row if row.get("pass_name") == resolved_only_pass),
            None,
        )
    elif isinstance(capability_row, dict):
        capability_row = capability_row.get(resolved_only_pass)
    if capability_row is None:
        capability_row = capability_map.get(resolved_only_pass)
    if capability_row is None:
        capability_row = (
            dict(summary.get("report_views", {}) or {})
            .get("only_pass", {})
            .get(resolved_only_pass, {})
            .get("capabilities")
        )
    _render_only_pass_sections(
        resolved_only_pass,
        {
            "symbolic_summary": pass_symbolic_summary,
            "evidence": pass_evidence,
            "validation_context": pass_validation_context,
            "region_evidence": pass_region_evidence,
            "capabilities": capability_row,
        },
    )
