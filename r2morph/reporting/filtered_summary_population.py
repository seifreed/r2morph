"""Filtered-summary population helpers.

These helpers populate the mutable filtered_summary structure after the
section payloads are resolved.
"""

from typing import Any

from r2morph.reporting.filtered_summary_pass_details import (
    _populate_pass_capabilities_and_context,
    _populate_pass_evidence,
)
from r2morph.reporting.filtered_summary_risk import _apply_risk_filters
from r2morph.reporting.filtered_summary_symbolic import (
    _populate_filtered_summary_symbolic_sections,
    _populate_symbolic_coverage_and_severity,
    _populate_symbolic_issue_passes,
)
from r2morph.reporting.filtered_summary_symbolic_fallbacks import (
    _build_filtered_summary_symbolic_fallback_sections,
)
from r2morph.reporting.filtered_summary_triage import _populate_triage_and_results
from r2morph.reporting.report_view_resolution import _resolve_summary_pass_sources


def _populate_filtered_summary_pass_sections(
    *,
    filtered_summary: dict[str, Any],
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    pass_support: dict[str, Any],
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_passes: list[dict[str, Any]],
    degradation_roles: dict[str, int],
    by_pass: dict[str, dict[str, int]],
    normalized_pass_map: dict[str, dict[str, Any]],
    selected_risk_pass_names: set[str],
    resolved_only_pass: str | None,
    only_risky_filters: bool,
    only_degraded: bool,
) -> dict[str, int]:
    """Populate filtered_summary pass-related sections using summary-first data."""
    summary_sources = _resolve_summary_pass_sources(summary)
    summary_pass_validation_context = summary_sources["pass_validation_context"]
    summary_pass_symbolic_summary = summary_sources["pass_symbolic_summary"]
    summary_pass_capabilities = summary_sources["pass_capabilities"]
    summary_pass_evidence_map = summary_sources["pass_evidence_map"]
    summary_pass_region_evidence_map = summary_sources["pass_region_evidence_map"]
    summary_pass_triage_map = summary_sources["pass_triage_map"]
    summary_normalized_pass_results = summary_sources["normalized_pass_results"]
    summary_symbolic_issue_map = summary_sources["symbolic_issue_map"]
    summary_symbolic_coverage_map = summary_sources["symbolic_coverage_map"]
    summary_symbolic_severity_map = summary_sources["symbolic_severity_map"]
    summary_pass_capability_summary_map = summary_sources["pass_capability_summary_map"]
    summary_validation_role_map = summary_sources["validation_role_map"]
    summary_discarded_mutation_summary = summary_sources["discarded_mutation_summary"]
    summary_discarded_mutation_priority = summary_sources["discarded_mutation_priority"]
    summary_pass_evidence_compact = summary_sources["pass_evidence_compact"]
    summary_report_views = summary_sources["report_views"]
    summary_discarded_view = summary_sources["discarded_view"]
    summary_general_passes = summary_sources["general_passes"]
    summary_general_pass_rows = summary_sources["general_pass_rows"]
    summary_general_symbolic = summary_sources["general_symbolic"]
    summary_general_discards = summary_sources["general_discards"]

    _populate_pass_capabilities_and_context(
        filtered_summary=filtered_summary,
        pass_results=pass_results,
        pass_support=pass_support,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degradation_roles=degradation_roles,
        normalized_pass_map=normalized_pass_map,
        summary_pass_capabilities=summary_pass_capabilities,
        summary_pass_validation_context=summary_pass_validation_context,
    )
    _populate_filtered_summary_symbolic_sections(
        filtered_summary=filtered_summary,
        summary=summary,
        pass_results=pass_results,
        by_pass=by_pass,
        degraded_passes=degraded_passes,
        only_degraded=only_degraded,
        summary_symbolic_issue_map=summary_symbolic_issue_map,
        summary_symbolic_coverage_map=summary_symbolic_coverage_map,
        summary_symbolic_severity_map=summary_symbolic_severity_map,
        summary_pass_symbolic_summary=summary_pass_symbolic_summary,
    )
    _populate_symbolic_issue_passes(
        filtered_summary=filtered_summary,
        summary=summary,
        pass_results=pass_results,
        by_pass=by_pass,
        summary_symbolic_issue_map=summary_symbolic_issue_map,
        summary_pass_evidence_compact=summary_pass_evidence_compact,
        summary_pass_evidence_map=summary_pass_evidence_map,
        summary_general_symbolic=summary_general_symbolic,
    )
    _populate_symbolic_coverage_and_severity(
        filtered_summary=filtered_summary,
        by_pass=by_pass,
        degraded_passes=degraded_passes,
        only_degraded=only_degraded,
        summary_symbolic_coverage_map=summary_symbolic_coverage_map,
        summary_symbolic_severity_map=summary_symbolic_severity_map,
        pass_results=pass_results,
    )

    filtered_summary["degradation_roles"] = degradation_roles
    for pass_name in filtered_summary["passes"]:
        pass_symbolic_summary = summary_pass_symbolic_summary.get(
            pass_name, pass_results.get(pass_name, {}).get("symbolic_summary")
        )
        if not pass_symbolic_summary:
            normalized_row = normalized_pass_map.get(pass_name, {})
            if normalized_row:
                pass_symbolic_summary = {
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
        if pass_symbolic_summary:
            filtered_summary["pass_symbolic_summary"][pass_name] = dict(pass_symbolic_summary)

    if not filtered_summary["pass_validation_context"] and summary_pass_validation_context:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_validation_context"] = {
            pass_name: dict(context)
            for pass_name, context in summary_pass_validation_context.items()
            if not visible_passes or pass_name in visible_passes
        }
    if not filtered_summary["pass_symbolic_summary"] and summary_pass_symbolic_summary:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_symbolic_summary"] = {
            pass_name: dict(summary_row)
            for pass_name, summary_row in summary_pass_symbolic_summary.items()
            if not visible_passes or pass_name in visible_passes
        }
    if not filtered_summary["pass_capabilities"] and summary_pass_capabilities:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_capabilities"] = {
            pass_name: dict(capabilities)
            for pass_name, capabilities in summary_pass_capabilities.items()
            if not visible_passes or pass_name in visible_passes
        }

    _populate_triage_and_results(
        filtered_summary=filtered_summary,
        summary=summary,
        summary_pass_triage_map=summary_pass_triage_map,
        summary_normalized_pass_results=summary_normalized_pass_results,
        summary_pass_capability_summary_map=summary_pass_capability_summary_map,
        summary_validation_role_map=summary_validation_role_map,
        summary_report_views=summary_report_views,
        summary_general_pass_rows=summary_general_pass_rows,
        summary_general_passes=summary_general_passes,
        summary_discarded_mutation_summary=summary_discarded_mutation_summary,
        summary_discarded_view=summary_discarded_view,
        summary_discarded_mutation_priority=summary_discarded_mutation_priority,
        summary_general_discards=summary_general_discards,
    )
    _populate_pass_evidence(
        filtered_summary=filtered_summary,
        pass_results=pass_results,
        normalized_pass_map=normalized_pass_map,
        selected_risk_pass_names=selected_risk_pass_names,
        resolved_only_pass=resolved_only_pass,
        only_risky_filters=only_risky_filters,
        summary_pass_region_evidence_map=summary_pass_region_evidence_map,
        summary_pass_evidence_map=summary_pass_evidence_map,
        summary_general_pass_rows=summary_general_pass_rows,
    )
    _apply_risk_filters(
        filtered_summary=filtered_summary,
        selected_risk_pass_names=selected_risk_pass_names,
        only_risky_filters=only_risky_filters,
    )

    if not filtered_summary["symbolic_issue_passes"] and by_pass:
        filtered_summary["symbolic_issue_passes"] = _build_filtered_summary_symbolic_fallback_sections(
            by_pass=by_pass,
        )["symbolic_issue_passes"]
    if not filtered_summary["symbolic_coverage_by_pass"] and by_pass:
        filtered_summary["symbolic_coverage_by_pass"] = _build_filtered_summary_symbolic_fallback_sections(
            by_pass=by_pass,
        )["symbolic_coverage_by_pass"]
    if by_pass and (
        not filtered_summary["symbolic_severity_by_pass"]
        or all(row.get("severity") == "not-requested" for row in filtered_summary["symbolic_severity_by_pass"])
    ):
        filtered_summary["symbolic_severity_by_pass"] = _build_filtered_summary_symbolic_fallback_sections(
            by_pass=by_pass,
        )["symbolic_severity_by_pass"]

    return degradation_roles
