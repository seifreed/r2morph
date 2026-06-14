"""Report orchestration: dispatch between general and mismatch-specific report flows."""

from __future__ import annotations

from r2morph.reporting.report_context import ReportFlowContext
from r2morph.reporting.report_flow_executor import (
    _execute_general_report_flow,
    _execute_only_mismatches_report_flow,
)
from r2morph.reporting.report_orchestrator_args import (
    build_general_report_flow_args,
    build_only_mismatches_report_flow_args,
)
from r2morph.reporting.report_orchestrator_context import build_report_flow_context
from r2morph.reporting.report_rendering_sections import _render_report_filter_messages


def _dispatch_report_flow_ctx(ctx: ReportFlowContext) -> None:
    """Dispatch between general and mismatch-specific report flows."""
    _render_report_filter_messages(
        only_pass=ctx.filters.only_pass,
        resolved_only_pass=ctx.severity.resolved_only_pass,
        only_pass_failure=ctx.filters.only_pass_failure,
        resolved_only_pass_failure=ctx.severity.resolved_only_pass_failure,
        only_risky_passes=ctx.filters.only_risky_passes,
        only_uncovered_passes=ctx.filters.only_uncovered_passes,
        only_covered_passes=ctx.filters.only_covered_passes,
        only_clean_passes=ctx.filters.only_clean_passes,
        only_structural_risk=ctx.filters.only_structural_risk,
        only_symbolic_risk=ctx.filters.only_symbolic_risk,
        selected_risk_pass_names=ctx.severity.selected_risk_pass_names,
    )
    if ctx.filters.only_mismatches:
        _execute_only_mismatches_report_flow(**build_only_mismatches_report_flow_args(ctx))
        return

    _execute_general_report_flow(**build_general_report_flow_args(ctx))


def _dispatch_report_flow(**kwargs: object) -> None:
    """Backward-compatible wrapper that constructs ReportFlowContext from kwargs."""
    ctx = build_report_flow_context(**kwargs)
    _dispatch_report_flow_ctx(ctx)
