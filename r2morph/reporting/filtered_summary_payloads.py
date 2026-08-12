"""Filtered-summary payload construction helpers.

These helpers build report payloads and report_filters data without owning
dispatch state or CLI emission concerns.
"""

from typing import Any

from r2morph.reporting.filtered_summary_degradation import _build_filtered_summary_degradation_sections
from r2morph.reporting.filtered_summary_gate import _build_filtered_summary_gate_sections
from r2morph.reporting.filtered_summary_mismatch_payloads import (
    _build_report_filters,
)
from r2morph.reporting.filtered_summary_population import _populate_filtered_summary_pass_sections
from r2morph.reporting.filtered_summary_risk_coverage import _build_filtered_summary_risk_coverage_sections
from r2morph.reporting.report_builder_models import ReportContext
from r2morph.reporting.report_context import FilterFlags, ReportFlowContext
from r2morph.reporting.report_pass_list_resolution import resolve_general_filtered_passes
from r2morph.reporting.report_view_resolution import _resolve_general_report_views


def _resolve_view_fallback(
    existing: dict[str, Any],
    renderer_value: Any,
    row_value: dict[str, Any],
    wrapper: str | None,
) -> dict[str, Any]:
    if existing:
        return existing
    value = dict(renderer_value or {}) or {key: item for key, item in row_value.items() if key != "section"}
    return {wrapper: value} if wrapper and value else value


def _symbolic_status_counts(summary: dict[str, Any], mutations: list[dict[str, Any]]) -> dict[str, int]:
    persisted = dict(summary.get("symbolic_status_counts", {}) or {})
    if persisted:
        return persisted
    counts: dict[str, int] = {}
    for mutation in mutations:
        status = mutation.get("metadata", {}).get("symbolic_status")
        if status:
            counts[status] = counts.get(status, 0) + 1
    return counts


def _build_base_filtered_summary(
    context: ReportContext,
    general_state: dict[str, Any],
    symbolic_state: dict[str, Any],
) -> dict[str, Any]:
    """Build the base filtered_summary payload used by general report views."""
    summary = context.summary
    mutations = general_state["mutations"]
    schema_version = summary.get("schema_version")
    resolved_general_views = _resolve_general_report_views(summary)
    summary_report_views = resolved_general_views["report_views"]
    general_renderer_state = resolved_general_views["general_renderer_state"]
    general_summary_rows = resolved_general_views["general_summary_rows"]
    general_summary_rows_by_section = {
        str(row.get("section")): dict(row) for row in general_summary_rows if row.get("section")
    }
    general_summary_view = _resolve_view_fallback(
        resolved_general_views["general_summary"],
        general_renderer_state.get("summary"),
        general_summary_rows_by_section.get("passes", {}),
        None,
    )
    general_symbolic_view = _resolve_view_fallback(
        resolved_general_views["general_symbolic"],
        general_renderer_state.get("symbolic"),
        general_summary_rows_by_section.get("symbolic", {}),
        "overview",
    )
    general_gates_view = _resolve_view_fallback(
        resolved_general_views["general_gates"],
        general_renderer_state.get("gates"),
        general_summary_rows_by_section.get("gates", {}),
        "compact_summary",
    )
    general_degradation_view = _resolve_view_fallback(
        resolved_general_views["general_degradation"],
        general_renderer_state.get("degradation"),
        general_summary_rows_by_section.get("degradation", {}),
        "summary",
    )
    general_discards_view = _resolve_view_fallback(
        resolved_general_views["general_discards"],
        general_renderer_state.get("discards"),
        general_summary_rows_by_section.get("discards", {}),
        "summary",
    )
    symbolic_overview = dict(general_symbolic_view.get("overview", {}) or {})
    filtered_summary = {
        "schema_version": schema_version,
        "mutations": len(mutations),
        "passes": sorted(
            {mutation.get("pass_name", "unknown") for mutation in mutations}
            or {str(row.get("pass_name")) for row in summary.get("normalized_pass_results", []) if row.get("pass_name")}
        ),
        "symbolic_requested": int(symbolic_overview.get("symbolic_requested", symbolic_state["symbolic_requested"])),
        "observable_match": int(symbolic_overview.get("observable_match", symbolic_state["observable_match"])),
        "observable_mismatch": int(symbolic_overview.get("observable_mismatch", symbolic_state["observable_mismatch"])),
        "bounded_only": int(symbolic_overview.get("bounded_only", symbolic_state["bounded_only"])),
        "without_symbolic_coverage": int(
            symbolic_overview.get("without_coverage", symbolic_state["observable_not_run"])
        ),
        "symbolic_issue_passes": [],
        "symbolic_coverage_by_pass": [],
        "symbolic_severity_by_pass": [],
        "symbolic_statuses": {},
        "pass_capabilities": {},
        "pass_validation_context": {},
        "pass_symbolic_summary": {},
        "pass_evidence": [],
        "pass_triage_rows": [],
        "normalized_pass_results": [],
        "pass_capability_summary": [],
        "validation_role_rows": [],
        "degradation_roles": {},
        "gate_failure_priority": list(context.gate_failure_priority),
        "gate_failure_severity_priority": list(context.gate_failure_severity_priority),
        "general_summary": general_summary_view,
        "general_summary_rows": general_summary_rows,
        "general_renderer_state": general_renderer_state,
        "general_symbolic": general_symbolic_view,
        "general_gates": general_gates_view,
        "general_degradation": general_degradation_view,
        "general_discards": general_discards_view,
        "general_filter_views": dict(
            summary_report_views.get("general_filter_views")
            or general_renderer_state.get("general_filter_views")
            or general_renderer_state.get("filter_views")
            or {}
        ),
        "general_triage_rows": list(
            summary_report_views.get("general_triage_rows")
            or general_renderer_state.get("general_triage_rows")
            or general_renderer_state.get("triage_rows")
            or []
        ),
    }
    filtered_summary.update(
        _build_filtered_summary_risk_coverage_sections(
            summary,
            general_state,
        )
    )
    filtered_summary.update(
        _build_filtered_summary_degradation_sections(
            context,
            degraded_passes=general_state["degraded_passes"],
        )
    )
    filtered_summary.update(
        _build_filtered_summary_gate_sections(
            context,
        )
    )
    filtered_summary["symbolic_statuses"] = _symbolic_status_counts(summary, mutations)
    return filtered_summary


def _build_general_filtered_summary(
    context: ReportContext,
    filters: FilterFlags,
    general_state: dict[str, Any],
    symbolic_state: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, int]]:
    """Build the general filtered_summary payload for report()."""
    filtered_summary = _build_base_filtered_summary(context, general_state, symbolic_state)
    filtered_summary["passes"] = resolve_general_filtered_passes(filtered_summary, context, filters, general_state)
    degradation_roles = _populate_filtered_summary_pass_sections(
        filtered_summary,
        context,
        filters,
        general_state,
        symbolic_state,
    )
    return filtered_summary, degradation_roles


def _build_general_report_payload(
    ctx: ReportFlowContext,
) -> dict[str, Any]:
    """Build the filtered payload for the general report path."""
    filtered_payload = dict(ctx.data.payload)
    filtered_payload["mutations"] = ctx.data.mutations
    filtered_payload["filtered_summary"] = ctx.data.filtered_summary
    report_filters = _build_report_filters(ctx.filters, ctx.severity)
    if report_filters:
        filtered_payload["report_filters"] = report_filters
    if ctx.severity.min_severity is not None:
        filtered_payload["filtered_summary"]["min_severity"] = ctx.severity.min_severity
    if ctx.filters.only_expected_severity is not None:
        filtered_payload["filtered_summary"]["only_expected_severity"] = ctx.filters.only_expected_severity
    if ctx.severity.resolved_only_pass_failure is not None:
        filtered_payload["filtered_summary"]["only_pass_failure"] = ctx.severity.resolved_only_pass_failure
    return filtered_payload
