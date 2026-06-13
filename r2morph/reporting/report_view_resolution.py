"""Summary-first resolution helpers for reporting views."""

from __future__ import annotations

from typing import Any


def _first_available(*sources: Any) -> Any:
    """Return the first truthy value from sources, or the last one."""
    for source in sources:
        if source:
            return source
    return sources[-1] if sources else None


def _resolve_general_report_views(summary: dict[str, Any]) -> dict[str, Any]:
    """Resolve summary-first general report views with renderer-state fallbacks."""
    summary_report_views = dict(summary.get("report_views", {}) or {})
    general_renderer_state = dict(summary_report_views.get("general_renderer_state", {}) or {})
    general_summary_view = dict(summary_report_views.get("general_summary", {}) or {})
    general_symbolic_view = dict(summary_report_views.get("general_symbolic", {}) or {})
    general_gates_view = dict(summary_report_views.get("general_gates", {}) or {})
    general_degradation_view = dict(summary_report_views.get("general_degradation", {}) or {})
    general_discards_view = dict(summary_report_views.get("general_discards", {}) or {})
    general_summary_rows = list(
        _first_available(
            list(summary_report_views.get("general_summary_rows", []) or []),
            list(general_renderer_state.get("general_summary_rows", []) or []),
            list(general_renderer_state.get("summary_rows", []) or []),
        )
        or []
    )
    general_summary_view = _first_available(
        general_summary_view,
        dict(general_renderer_state.get("general_summary", {}) or {}),
    )
    if not general_symbolic_view and general_renderer_state.get("general_symbolic"):
        general_symbolic_view = {"overview": dict(general_renderer_state.get("general_symbolic", {}) or {})}
    if not general_gates_view and general_renderer_state.get("general_gates"):
        general_gates_view = {"compact_summary": dict(general_renderer_state.get("general_gates", {}) or {})}
    if not general_degradation_view and general_renderer_state.get("general_degradation"):
        general_degradation_view = {"summary": dict(general_renderer_state.get("general_degradation", {}) or {})}
    if not general_discards_view and general_renderer_state.get("general_discards"):
        general_discards_view = {"summary": dict(general_renderer_state.get("general_discards", {}) or {})}

    return {
        "report_views": summary_report_views,
        "general_renderer_state": general_renderer_state,
        "general_summary_rows": general_summary_rows,
        "general_summary": general_summary_view,
        "general_symbolic": general_symbolic_view,
        "general_gates": general_gates_view,
        "general_degradation": general_degradation_view,
        "general_discards": general_discards_view,
    }


def _resolve_summary_pass_sources(summary: dict[str, Any]) -> dict[str, Any]:
    """Resolve summary-first pass-related sources in one place."""
    resolved_general_views = _resolve_general_report_views(summary)
    report_views = resolved_general_views["report_views"]
    general_renderer_state = resolved_general_views["general_renderer_state"]
    general_renderer_passes = list(general_renderer_state.get("passes", []) or [])
    general_renderer_general_passes = list(general_renderer_state.get("general_passes", []) or [])
    general_renderer_general_pass_rows = list(general_renderer_state.get("general_pass_rows", []) or [])
    general_renderer_pass_rows = list(
        general_renderer_state.get(
            "pass_rows",
            general_renderer_general_pass_rows or general_renderer_general_passes or general_renderer_passes,
        )
        or general_renderer_general_pass_rows
        or general_renderer_general_passes
        or general_renderer_passes
    )
    general_renderer_triage_rows = list(
        general_renderer_state.get(
            "general_triage_rows",
            general_renderer_state.get("triage_rows", []),
        )
        or []
    )
    return {
        "pass_validation_context": dict(summary.get("pass_validation_context", {}) or {}),
        "pass_symbolic_summary": dict(summary.get("pass_symbolic_summary", {}) or {}),
        "pass_capabilities": dict(summary.get("pass_capabilities", {}) or {}),
        "pass_evidence_map": dict(summary.get("pass_evidence_map", {}) or {}),
        "pass_region_evidence_map": dict(summary.get("pass_region_evidence_map", {}) or {}),
        "pass_triage_map": dict(summary.get("pass_triage_map", {}) or {}),
        "normalized_pass_results": list(summary.get("normalized_pass_results", []) or []),
        "symbolic_issue_map": dict(summary.get("symbolic_issue_map", {}) or {}),
        "symbolic_coverage_map": dict(summary.get("symbolic_coverage_map", {}) or {}),
        "symbolic_severity_map": dict(summary.get("symbolic_severity_map", {}) or {}),
        "pass_capability_summary_map": dict(summary.get("pass_capability_summary_map", {}) or {}),
        "validation_role_map": dict(summary.get("validation_role_map", {}) or {}),
        "discarded_mutation_summary": dict(summary.get("discarded_mutation_summary", {}) or {}),
        "discarded_mutation_priority": list(summary.get("discarded_mutation_priority", []) or []),
        "pass_evidence_compact": list(summary.get("pass_evidence_compact", [])),
        "report_views": report_views,
        "discarded_view": dict(report_views.get("discarded_view", {}) or {}),
        "general_passes": list(
            report_views.get("general_passes", []) or general_renderer_general_passes or general_renderer_passes
        ),
        "general_pass_rows": list(report_views.get("general_pass_rows", []) or general_renderer_pass_rows),
        "general_summary": resolved_general_views["general_summary"],
        "general_symbolic": resolved_general_views["general_symbolic"],
        "general_gates": resolved_general_views["general_gates"],
        "general_degradation": resolved_general_views["general_degradation"],
        "general_discards": resolved_general_views["general_discards"],
        "general_triage_rows": list(report_views.get("general_triage_rows", []) or general_renderer_triage_rows),
    }


def _resolve_general_filtered_passes(
    *,
    existing_passes: list[str],
    summary_only_pass_view: dict[str, Any],
    summary_general_passes: list[dict[str, Any]],
    summary_general_pass_rows: list[dict[str, Any]],
    summary_general_summary: dict[str, Any],
    resolved_only_pass: str | None,
    selected_risk_pass_names: set[str],
    only_risky_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_failed_gates: bool,
    gate_failure_priority: list[dict[str, Any]],
) -> list[str]:
    """Resolve the visible pass list for the general report path."""
    resolved_passes = list(existing_passes)
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
    if (
        only_risky_passes
        or only_structural_risk
        or only_symbolic_risk
        or only_uncovered_passes
        or only_covered_passes
        or only_clean_passes
    ):
        return sorted(
            pass_name
            for pass_name in selected_risk_pass_names
            if resolved_only_pass is None or pass_name == resolved_only_pass
        )
    if resolved_only_pass and not resolved_passes:
        all_known = (
            set(existing_passes)
            | {str(row.get("pass_name")) for row in summary_general_passes if row.get("pass_name")}
            | {str(row.get("pass_name")) for row in summary_general_pass_rows if row.get("pass_name")}
            | set(summary_only_pass_view)
        )
        if resolved_only_pass in all_known:
            return [resolved_only_pass]
        return []
    if only_failed_gates and not resolved_passes and gate_failure_priority:
        return sorted({str(row.get("pass_name")) for row in gate_failure_priority if row.get("pass_name")})
    if resolved_only_pass and resolved_passes:
        return [p for p in resolved_passes if p == resolved_only_pass]
    return resolved_passes
