"""Report orchestration: dispatch between general and mismatch-specific report flows."""

from __future__ import annotations

from r2morph.reporting.report_context import ReportFlowContext
from r2morph.reporting.report_flow_executor import (
    _execute_general_report_flow,
    _execute_only_mismatches_report_flow,
)
from r2morph.reporting.report_rendering_sections import _render_report_filter_messages


def _dispatch_report_flow_ctx(ctx: ReportFlowContext) -> None:
    """Dispatch between general and mismatch-specific report flows."""
    _render_report_filter_messages(ctx)
    if ctx.filters.only_mismatches:
        _execute_only_mismatches_report_flow(ctx)
        return

    _execute_general_report_flow(ctx)
