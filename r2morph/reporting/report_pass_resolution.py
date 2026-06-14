"""Pass-scoped report resolution helpers."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_state import _normalized_pass_map as _normalized_pass_map_state


def resolve_only_pass_view(
    *,
    summary: dict[str, Any],
    filtered_summary: dict[str, Any],
    pass_results: dict[str, Any],
    pass_name: str,
) -> tuple[
    dict[str, Any] | None,
    dict[str, Any] | None,
    dict[str, Any] | None,
    list[dict[str, Any]] | None,
]:
    """Resolve pass-scoped symbolic/evidence/context views with summary-first fallbacks."""
    report_views = dict(summary.get("report_views", {}) or {})
    only_pass_map = dict(report_views.get("only_pass", {}) or {})
    summary_pass_symbolic_summary = dict(summary.get("pass_symbolic_summary", {}) or {})
    summary_pass_validation_context = dict(summary.get("pass_validation_context", {}) or {})
    summary_pass_region_evidence_map = dict(summary.get("pass_region_evidence_map", {}) or {})
    normalized_pass_map = _normalized_pass_map_state(list(summary.get("normalized_pass_results", []) or []))
    symbolic_summary = filtered_summary.get("pass_symbolic_summary", {}).get(pass_name)
    if symbolic_summary is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        symbolic_summary = compact_row.get("symbolic_summary") or summary_pass_symbolic_summary.get(pass_name)
    if symbolic_summary is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        normalized_row = normalized_pass_map.get(pass_name) or compact_row.get("normalized") or compact_row
        if normalized_row:
            symbolic_summary = {
                "pass_name": pass_name,
                "severity": normalized_row.get("severity", "not-requested"),
                "issue_count": normalized_row.get("issue_count", 0),
                "symbolic_requested": normalized_row.get("symbolic_requested", 0),
                "observable_match": normalized_row.get("observable_match", 0),
                "observable_mismatch": normalized_row.get("observable_mismatch", 0),
                "bounded_only": normalized_row.get("bounded_only", 0),
                "without_coverage": normalized_row.get("without_coverage", 0),
                "issues": [],
            }
    pass_evidence = next(
        (row for row in filtered_summary.get("pass_evidence", []) if row.get("pass_name") == pass_name),
        None,
    )
    if pass_evidence is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        pass_evidence = compact_row.get("evidence")
        normalized_row = normalized_pass_map.get(pass_name) or compact_row.get("normalized") or compact_row
        if normalized_row:
            pass_evidence = pass_evidence or {
                "pass_name": pass_name,
                "changed_region_count": normalized_row.get("changed_region_count", 0),
                "changed_bytes": normalized_row.get("changed_bytes", 0),
                "structural_issue_count": normalized_row.get("structural_issue_count", 0),
                "symbolic_binary_mismatched_regions": normalized_row.get("symbolic_binary_mismatched_regions", 0),
            }
    context = filtered_summary.get("pass_validation_context", {}).get(pass_name)
    if context is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        context = compact_row.get("validation_context") or summary_pass_validation_context.get(
            pass_name, pass_results.get(pass_name, {}).get("validation_context")
        )
    if context is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        normalized_row = normalized_pass_map.get(pass_name) or compact_row.get("normalized") or compact_row
        if normalized_row:
            role = normalized_row.get("role", "requested-mode")
            context = {
                "role": role,
                "requested_validation_mode": filtered_summary.get("requested_validation_mode", "off"),
                "effective_validation_mode": filtered_summary.get("validation_mode", "off"),
                "degraded_execution": role == "executed-under-degraded-mode",
                "degradation_triggered_by_pass": role == "degradation-trigger",
            }
    region_evidence = summary_pass_region_evidence_map.get(pass_name)
    if region_evidence is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        region_evidence = compact_row.get("region_evidence")
    return symbolic_summary, pass_evidence, context, region_evidence
