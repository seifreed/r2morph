"""Resolve the visible pass list for reporting."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_builder_models import ReportContext
from r2morph.reporting.report_context import FilterFlags
from r2morph.reporting.report_view_resolution import _resolve_summary_pass_sources


def resolve_general_filtered_passes(
    filtered_summary: dict[str, Any],
    context: ReportContext,
    filters: FilterFlags,
    general_state: dict[str, Any],
) -> list[str]:
    """Resolve the visible pass list for the general report path."""
    summary_sources = _resolve_summary_pass_sources(context.summary)
    summary_report_views = summary_sources["report_views"]
    summary_only_pass_view = dict(summary_report_views.get("only_pass", {}) or {})
    summary_general_passes = summary_sources["general_passes"]
    summary_general_pass_rows = summary_sources["general_pass_rows"]
    summary_general_summary = summary_sources["general_summary"] or filtered_summary.get("general_summary", {})
    resolved_only_pass = context.resolved_only_pass
    selected_risk_pass_names = general_state["selected_risk_pass_names"]
    resolved_passes = list(filtered_summary["passes"])
    if not resolved_passes and summary_general_summary.get("passes"):
        resolved_passes = [str(pass_name) for pass_name in list(summary_general_summary.get("passes", [])) if pass_name]
    if not resolved_passes and summary_general_passes:
        resolved_passes = sorted({str(row.get("pass_name")) for row in summary_general_passes if row.get("pass_name")})
    if not resolved_passes and summary_general_pass_rows:
        resolved_passes = sorted(
            {str(row.get("pass_name")) for row in summary_general_pass_rows if row.get("pass_name")}
        )
    if resolved_only_pass and not resolved_passes and resolved_only_pass in summary_only_pass_view:
        resolved_passes = [resolved_only_pass]
    if filters.pass_classes.any_active:
        return sorted(
            pass_name
            for pass_name in selected_risk_pass_names
            if resolved_only_pass is None or pass_name == resolved_only_pass
        )
    if resolved_only_pass and not resolved_passes:
        all_known = (
            set(filtered_summary["passes"])
            | {str(row.get("pass_name")) for row in summary_general_passes if row.get("pass_name")}
            | {str(row.get("pass_name")) for row in summary_general_pass_rows if row.get("pass_name")}
            | set(summary_only_pass_view)
        )
        if resolved_only_pass in all_known:
            return [resolved_only_pass]
        return []
    if filters.only_failed_gates and not resolved_passes and context.gate_failure_priority:
        return sorted({str(row.get("pass_name")) for row in context.gate_failure_priority if row.get("pass_name")})
    if resolved_only_pass and resolved_passes:
        return [p for p in resolved_passes if p == resolved_only_pass]
    return resolved_passes
