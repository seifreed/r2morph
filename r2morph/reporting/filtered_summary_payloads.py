"""Filtered-summary payload construction helpers.

These helpers build report payloads and report_filters data without owning
dispatch state or CLI emission concerns.
"""

from typing import Any

from r2morph.reporting.filtered_summary_mismatch_payloads import (
    _build_only_mismatches_filtered_summary,  # noqa: F401
    _build_only_mismatches_payload,  # noqa: F401
    _build_report_filters,
)
from r2morph.reporting.filtered_summary_sections import (
    _build_filtered_summary_degradation_sections,
    _build_filtered_summary_gate_sections,
    _build_filtered_summary_risk_coverage_sections,
    _populate_filtered_summary_pass_sections,
)
from r2morph.reporting.report_view_resolution import _resolve_general_filtered_passes, _resolve_general_report_views


def _build_base_filtered_summary(
    *,
    mutations: list[dict[str, Any]],
    symbolic_requested: int,
    observable_match: int,
    observable_mismatch: int,
    bounded_only: int,
    observable_not_run: int,
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    degraded_passes: list[dict[str, Any]],
    risky_pass_names: set[str],
    structural_risk_pass_names: set[str],
    symbolic_risk_pass_names: set[str],
    covered_pass_names: set[str],
    uncovered_pass_names: set[str],
    clean_pass_names: set[str],
    failed_gates: bool,
    validation_policy: dict[str, Any] | None,
    gate_evaluation: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the base filtered_summary payload used by general report views."""
    schema_version = summary.get("schema_version")
    resolved_general_views = _resolve_general_report_views(summary)
    summary_report_views = resolved_general_views["report_views"]
    general_renderer_state = resolved_general_views["general_renderer_state"]
    general_summary_rows = resolved_general_views["general_summary_rows"]
    general_summary_view = resolved_general_views["general_summary"]
    general_symbolic_view = resolved_general_views["general_symbolic"]
    general_gates_view = resolved_general_views["general_gates"]
    general_degradation_view = resolved_general_views["general_degradation"]
    general_discards_view = resolved_general_views["general_discards"]
    symbolic_overview = dict(general_symbolic_view.get("overview", {}) or {})
    general_summary_rows_by_section = {
        str(row.get("section")): dict(row) for row in general_summary_rows if row.get("section")
    }
    if not general_summary_view and general_renderer_state.get("summary"):
        general_summary_view = dict(general_renderer_state.get("summary", {}) or {})
    if not general_summary_view and general_summary_rows_by_section.get("passes"):
        general_summary_view = {
            key: value for key, value in general_summary_rows_by_section["passes"].items() if key != "section"
        }
    if not general_symbolic_view and general_renderer_state.get("symbolic"):
        general_symbolic_view = {"overview": dict(general_renderer_state.get("symbolic", {}) or {})}
    if not general_symbolic_view and general_summary_rows_by_section.get("symbolic"):
        general_symbolic_view = {
            "overview": {
                key: value for key, value in general_summary_rows_by_section["symbolic"].items() if key != "section"
            }
        }
    if not general_gates_view and general_renderer_state.get("gates"):
        general_gates_view = {"compact_summary": dict(general_renderer_state.get("gates", {}) or {})}
    if not general_gates_view and general_summary_rows_by_section.get("gates"):
        general_gates_view = {
            "compact_summary": {
                key: value for key, value in general_summary_rows_by_section["gates"].items() if key != "section"
            }
        }
    if not general_degradation_view and general_renderer_state.get("degradation"):
        general_degradation_view = {"summary": dict(general_renderer_state.get("degradation", {}) or {})}
    if not general_degradation_view and general_summary_rows_by_section.get("degradation"):
        general_degradation_view = {
            "summary": {
                key: value for key, value in general_summary_rows_by_section["degradation"].items() if key != "section"
            }
        }
    if not general_discards_view and general_renderer_state.get("discards"):
        general_discards_view = {"summary": dict(general_renderer_state.get("discards", {}) or {})}
    if not general_discards_view and general_summary_rows_by_section.get("discards"):
        general_discards_view = {
            "summary": {
                key: value for key, value in general_summary_rows_by_section["discards"].items() if key != "section"
            }
        }
    if not symbolic_overview and general_renderer_state.get("symbolic"):
        symbolic_overview = dict(general_renderer_state.get("symbolic", {}) or {})
    if not symbolic_overview and general_symbolic_view.get("overview"):
        symbolic_overview = dict(general_symbolic_view.get("overview", {}) or {})
    filtered_summary = {
        "schema_version": schema_version,
        "mutations": len(mutations),
        "passes": sorted(
            {mutation.get("pass_name", "unknown") for mutation in mutations}
            or {str(row.get("pass_name")) for row in summary.get("normalized_pass_results", []) if row.get("pass_name")}
        ),
        "symbolic_requested": int(symbolic_overview.get("symbolic_requested", symbolic_requested)),
        "observable_match": int(symbolic_overview.get("observable_match", observable_match)),
        "observable_mismatch": int(symbolic_overview.get("observable_mismatch", observable_mismatch)),
        "bounded_only": int(symbolic_overview.get("bounded_only", bounded_only)),
        "without_symbolic_coverage": int(symbolic_overview.get("without_coverage", observable_not_run)),
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
        "gate_failure_priority": list(gate_failure_priority),
        "gate_failure_severity_priority": list(gate_failure_severity_priority),
        "general_summary": general_summary_view,
        "general_summary_rows": general_summary_rows,
        "general_renderer_state": general_renderer_state,
        "general_symbolic": general_symbolic_view,
        "general_gates": general_gates_view,
        "general_degradation": general_degradation_view,
        "general_discards": general_discards_view,
        "general_filter_views": dict(summary_report_views.get("general_filter_views", {}) or {}),
        "general_triage_rows": list(summary_report_views.get("general_triage_rows", []) or []),
    }
    if not filtered_summary["general_filter_views"] and general_renderer_state.get("general_filter_views"):
        filtered_summary["general_filter_views"] = dict(general_renderer_state.get("general_filter_views", {}) or {})
    if not filtered_summary["general_filter_views"] and general_renderer_state.get("filter_views"):
        filtered_summary["general_filter_views"] = dict(general_renderer_state.get("filter_views", {}) or {})
    if not filtered_summary["general_triage_rows"] and general_renderer_state.get("general_triage_rows"):
        filtered_summary["general_triage_rows"] = list(general_renderer_state.get("general_triage_rows", []) or [])
    if not filtered_summary["general_triage_rows"] and general_renderer_state.get("triage_rows"):
        filtered_summary["general_triage_rows"] = list(general_renderer_state.get("triage_rows", []) or [])
    filtered_summary.update(
        _build_filtered_summary_risk_coverage_sections(
            summary=summary,
            risky_pass_names=risky_pass_names,
            structural_risk_pass_names=structural_risk_pass_names,
            symbolic_risk_pass_names=symbolic_risk_pass_names,
            covered_pass_names=covered_pass_names,
            uncovered_pass_names=uncovered_pass_names,
            clean_pass_names=clean_pass_names,
        )
    )
    filtered_summary.update(
        _build_filtered_summary_degradation_sections(
            summary=summary,
            validation_policy=validation_policy,
            requested_validation_mode=requested_validation_mode,
            effective_validation_mode=effective_validation_mode,
            degraded_validation=degraded_validation,
            degraded_passes=degraded_passes,
        )
    )
    filtered_summary.update(
        _build_filtered_summary_gate_sections(
            summary=summary,
            gate_evaluation=gate_evaluation,
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            failed_gates=failed_gates,
        )
    )
    summary_symbolic_status_counts = dict(summary.get("symbolic_status_counts", {}) or {})
    if summary_symbolic_status_counts:
        filtered_summary["symbolic_statuses"] = dict(summary_symbolic_status_counts)
    else:
        for mutation in mutations:
            status = mutation.get("metadata", {}).get("symbolic_status")
            if not status:
                continue
            filtered_summary["symbolic_statuses"][status] = filtered_summary["symbolic_statuses"].get(status, 0) + 1
    return filtered_summary


def _build_general_filtered_summary(
    *,
    summary: dict[str, Any],
    mutations: list[dict[str, Any]],
    pass_results: dict[str, Any],
    pass_support: dict[str, Any],
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    degraded_passes: list[dict[str, Any]],
    risky_pass_names: set[str],
    structural_risk_pass_names: set[str],
    symbolic_risk_pass_names: set[str],
    covered_pass_names: set[str],
    uncovered_pass_names: set[str],
    clean_pass_names: set[str],
    failed_gates: bool,
    validation_policy: dict[str, Any] | None,
    gate_evaluation: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    symbolic_requested: int,
    observable_match: int,
    observable_mismatch: int,
    bounded_only: int,
    observable_not_run: int,
    by_pass: dict[str, dict[str, int]],
    degradation_roles: dict[str, int],
    normalized_pass_map: dict[str, dict[str, Any]],
    selected_risk_pass_names: set[str],
    resolved_only_pass: str | None,
    only_risky_filters: bool,
    only_degraded: bool,
    only_risky_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_failed_gates: bool,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Build the general filtered_summary payload for report()."""
    filtered_summary = _build_base_filtered_summary(
        mutations=mutations,
        symbolic_requested=symbolic_requested,
        observable_match=observable_match,
        observable_mismatch=observable_mismatch,
        bounded_only=bounded_only,
        observable_not_run=observable_not_run,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        degraded_passes=degraded_passes,
        risky_pass_names=risky_pass_names,
        structural_risk_pass_names=structural_risk_pass_names,
        symbolic_risk_pass_names=symbolic_risk_pass_names,
        covered_pass_names=covered_pass_names,
        uncovered_pass_names=uncovered_pass_names,
        clean_pass_names=clean_pass_names,
        failed_gates=failed_gates,
        validation_policy=validation_policy,
        gate_evaluation=gate_evaluation,
        gate_failure_summary=gate_failure_summary,
        summary=summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
    )
    summary_report_views = dict(summary.get("report_views", {}) or {})
    only_pass_view = dict(summary_report_views.get("only_pass", {}) or {})
    summary_general_passes = list(summary_report_views.get("general_passes", []) or [])
    summary_general_pass_rows = list(summary_report_views.get("general_pass_rows", []) or [])
    general_renderer_state = dict(summary_report_views.get("general_renderer_state", {}) or {})
    if not summary_general_pass_rows and general_renderer_state.get("general_pass_rows"):
        summary_general_pass_rows = list(general_renderer_state.get("general_pass_rows", []) or [])
    if not summary_general_passes and summary_general_pass_rows:
        summary_general_passes = list(summary_general_pass_rows)
    summary_general_summary = dict(summary_report_views.get("general_summary", {}) or {})
    if not summary_general_summary:
        summary_general_summary = dict(filtered_summary.get("general_summary", {}) or {})

    filtered_summary["passes"] = _resolve_general_filtered_passes(
        existing_passes=filtered_summary["passes"],
        summary_only_pass_view=only_pass_view,
        summary_general_passes=summary_general_passes,
        summary_general_pass_rows=summary_general_pass_rows,
        summary_general_summary=summary_general_summary,
        resolved_only_pass=resolved_only_pass,
        selected_risk_pass_names=selected_risk_pass_names,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        only_failed_gates=only_failed_gates,
        gate_failure_priority=gate_failure_priority,
    )
    degradation_roles = _populate_filtered_summary_pass_sections(
        filtered_summary=filtered_summary,
        summary=summary,
        pass_results=pass_results,
        pass_support=pass_support,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_passes=degraded_passes,
        degradation_roles=degradation_roles,
        by_pass=by_pass,
        normalized_pass_map=normalized_pass_map,
        selected_risk_pass_names=selected_risk_pass_names,
        resolved_only_pass=resolved_only_pass,
        only_risky_filters=only_risky_filters,
        only_degraded=only_degraded,
    )
    return filtered_summary, degradation_roles


def _build_general_report_payload(
    *,
    payload: dict[str, Any],
    mutations: list[dict[str, Any]],
    filtered_summary: dict[str, Any],
    resolved_only_pass: str | None,
    only_status: str | None,
    only_degraded: bool,
    only_failed_gates: bool,
    only_risky_passes: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    min_severity: str | None,
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
) -> dict[str, Any]:
    """Build the filtered payload for the general report path."""
    filtered_payload = dict(payload)
    filtered_payload["mutations"] = mutations
    filtered_payload["filtered_summary"] = filtered_summary
    report_filters = _build_report_filters(
        resolved_only_pass=resolved_only_pass,
        only_status=only_status,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_passes=only_risky_passes,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        min_severity=min_severity,
        only_expected_severity=only_expected_severity,
        resolved_only_pass_failure=resolved_only_pass_failure,
    )
    if report_filters:
        filtered_payload["report_filters"] = report_filters
    if min_severity is not None:
        filtered_payload["filtered_summary"]["min_severity"] = min_severity
    if only_expected_severity is not None:
        filtered_payload["filtered_summary"]["only_expected_severity"] = only_expected_severity
    if resolved_only_pass_failure is not None:
        filtered_payload["filtered_summary"]["only_pass_failure"] = resolved_only_pass_failure
    return filtered_payload
