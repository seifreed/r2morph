"""Filtered-summary section and population helpers.

Leaf detail-builders for filtered report payloads, extracted verbatim from
filtered_summary_builder.py -- no logic changes. These functions form a
one-directional layer: the orchestrating builders depend on them, never the
reverse. Symbolic-specific helpers live in filtered_summary_symbolic.
"""

from typing import Any

from r2morph.reporting.filtered_summary_population import (  # noqa: F401
    _apply_risk_filters,
    _populate_filtered_summary_discarded_sections,
    _populate_filtered_summary_pass_sections,
    _populate_pass_capabilities_and_context,
    _populate_pass_evidence,
    _populate_triage_and_results,
)
from r2morph.reporting.report_helpers import _summary_first
from r2morph.reporting.report_view_resolution import _resolve_general_report_views


def _build_filtered_summary_gate_sections(
    *,
    summary: dict[str, Any],
    gate_evaluation: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    failed_gates: bool,
) -> dict[str, Any]:
    """Build filtered_summary gate-related sections from persisted report views first."""
    resolved_general_views = _resolve_general_report_views(summary)
    report_views = resolved_general_views["report_views"]
    general_gates = resolved_general_views["general_gates"]
    persisted_view = dict(report_views.get("only_failed_gates", {}) or {})
    summary_payload = dict(
        persisted_view.get("summary", {})
        or general_gates.get("summary", {})
        or gate_failure_summary
        or general_gates.get("compact_summary", {})
    )
    priority_payload = list(persisted_view.get("priority", []) or gate_failure_priority)
    severity_payload = list(
        persisted_view.get("severity_priority", [])
        or general_gates.get("severity_priority", [])
        or gate_failure_severity_priority
    )
    compact_summary = dict(persisted_view.get("compact_summary", {}) or general_gates.get("compact_summary", {}) or {})
    final_rows = list(persisted_view.get("final_rows", []) or [])
    compact_rows = list(persisted_view.get("compact_rows", []) or [])
    final_by_pass = dict(persisted_view.get("final_by_pass", {}) or {})
    if not final_rows and priority_payload:
        if final_by_pass:
            final_rows = [dict(final_by_pass[pass_name]) for pass_name in sorted(final_by_pass)]
        else:
            final_rows = [
                {
                    "pass_name": str(row.get("pass_name", "")),
                    "failure_count": int(row.get("failure_count", 0)),
                    "strictest_expected_severity": row.get("strictest_expected_severity", "unknown"),
                    "role": row.get("role", "requested-mode"),
                    "failed": bool(row.get("failures")),
                    "failures": list(row.get("failures", [])),
                }
                for row in priority_payload
                if row.get("pass_name")
            ]
    elif final_rows:
        priority_by_pass = {
            str(row.get("pass_name", "")): dict(row) for row in priority_payload if row.get("pass_name")
        }
        enriched_final_rows = []
        for row in final_rows:
            pass_name = str(row.get("pass_name", ""))
            priority_row = priority_by_pass.get(pass_name, {})
            enriched = dict(row)
            if "failures" not in enriched and priority_row.get("failures") is not None:
                enriched["failures"] = list(priority_row.get("failures", []))
            enriched_final_rows.append(enriched)
        final_rows = enriched_final_rows
    if not compact_summary:
        compact_summary = {
            "failed": bool(persisted_view.get("failed", False) or failed_gates),
            "failure_count": int(
                persisted_view.get("failure_count", 0) or summary_payload.get("require_pass_severity_failure_count", 0)
            ),
            "pass_count": int(persisted_view.get("pass_count", 0)),
            "expected_severity_counts": dict(persisted_view.get("expected_severity_counts", {}) or {}),
            "severity_priority": severity_payload,
            "passes": list(persisted_view.get("passes", []) or []),
        }
    section: dict[str, Any] = {
        "failed_gates": failed_gates or bool(persisted_view.get("failed", False)),
        "gate_failure_priority": priority_payload,
        "gate_failure_severity_priority": severity_payload,
        "gate_failure_final_rows": final_rows,
        "gate_failure_final_by_pass": final_by_pass,
        "gate_failure_compact_rows": compact_rows,
        "gate_failure_compact_by_pass": dict(persisted_view.get("compact_by_pass", {}) or {}),
        "gate_failure_compact_summary": compact_summary,
    }
    if gate_evaluation:
        section["gate_evaluation"] = gate_evaluation
    if summary_payload:
        section["gate_failures"] = summary_payload
    return section


def _build_filtered_summary_risk_coverage_sections(
    *,
    summary: dict[str, Any],
    risky_pass_names: set[str],
    structural_risk_pass_names: set[str],
    symbolic_risk_pass_names: set[str],
    covered_pass_names: set[str],
    uncovered_pass_names: set[str],
    clean_pass_names: set[str],
) -> dict[str, Any]:
    """Build filtered_summary risk/coverage sections from persisted summary first."""
    report_views = dict(summary.get("report_views", {}) or {})
    general_renderer_state = dict(report_views.get("general_renderer_state", {}) or {})
    pass_risk_buckets = dict(_summary_first(summary, "pass_risk_buckets", {}) or {})
    pass_coverage_buckets = dict(_summary_first(summary, "pass_coverage_buckets", {}) or {})
    general_filter_views = dict(report_views.get("general_filter_views", {}) or {})
    if not general_filter_views and general_renderer_state.get("general_filter_views"):
        general_filter_views = dict(general_renderer_state.get("general_filter_views", {}) or {})
    if not general_filter_views and general_renderer_state.get("filter_views"):
        general_filter_views = dict(general_renderer_state.get("filter_views", {}) or {})
    risky = sorted(pass_risk_buckets.get("risky", list(risky_pass_names)) or list(risky_pass_names))
    if not risky and general_filter_views.get("risky"):
        risky = sorted(str(name) for name in general_filter_views.get("risky", []) if name)
    structural = sorted(
        pass_risk_buckets.get("structural", list(structural_risk_pass_names)) or list(structural_risk_pass_names)
    )
    if not structural and general_filter_views.get("structural_risk"):
        structural = sorted(str(name) for name in general_filter_views.get("structural_risk", []) if name)
    symbolic = sorted(
        pass_risk_buckets.get("symbolic", list(symbolic_risk_pass_names)) or list(symbolic_risk_pass_names)
    )
    if not symbolic and general_filter_views.get("symbolic_risk"):
        symbolic = sorted(str(name) for name in general_filter_views.get("symbolic_risk", []) if name)
    clean = sorted(pass_risk_buckets.get("clean", list(clean_pass_names)) or list(clean_pass_names))
    if not clean and general_filter_views.get("clean"):
        clean = sorted(str(name) for name in general_filter_views.get("clean", []) if name)
    covered = sorted(pass_coverage_buckets.get("covered", list(covered_pass_names)) or list(covered_pass_names))
    if not covered and general_filter_views.get("covered"):
        covered = sorted(str(name) for name in general_filter_views.get("covered", []) if name)
    uncovered = sorted(pass_coverage_buckets.get("uncovered", list(uncovered_pass_names)) or list(uncovered_pass_names))
    if not uncovered and general_filter_views.get("uncovered"):
        uncovered = sorted(str(name) for name in general_filter_views.get("uncovered", []) if name)
    clean_only = sorted(pass_coverage_buckets.get("clean_only", list(clean_pass_names)) or list(clean_pass_names))
    return {
        "pass_coverage_buckets": {
            "covered": covered,
            "uncovered": uncovered,
            "clean_only": clean_only,
        },
        "pass_risk_buckets": {
            "risky": risky,
            "structural": structural,
            "symbolic": symbolic,
            "clean": clean,
            "covered": covered,
            "uncovered": uncovered,
        },
        "risky_passes": risky,
        "structural_risk_passes": structural,
        "symbolic_risk_passes": symbolic,
        "covered_passes": covered,
        "uncovered_passes": uncovered,
        "clean_passes": clean,
    }


def _build_filtered_summary_degradation_sections(
    *,
    summary: dict[str, Any],
    validation_policy: dict[str, Any] | None,
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    degraded_passes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build filtered_summary degradation/validation-mode sections."""
    resolved_general_views = _resolve_general_report_views(summary)
    report_views = resolved_general_views["report_views"]
    validation_adjustments = dict(summary.get("validation_adjustments", {}) or {})
    general_degradation = resolved_general_views["general_degradation"]
    persisted_adjustments = dict(report_views.get("validation_adjustments", {}) or {})
    degradation_roles = dict(summary.get("degradation_roles", {}) or {})
    section: dict[str, Any] = {
        "requested_validation_mode": requested_validation_mode,
        "validation_mode": effective_validation_mode,
        "degraded_validation": degraded_validation,
        "degraded_passes": degraded_passes,
        "degradation_roles": degradation_roles,
    }
    if validation_policy is not None:
        section["validation_policy"] = validation_policy
    if general_degradation.get("summary"):
        section["validation_adjustments"] = dict(general_degradation.get("summary", {}))
    elif validation_adjustments:
        section["validation_adjustments"] = validation_adjustments
    if persisted_adjustments:
        if persisted_adjustments.get("by_pass"):
            section["validation_adjustment_by_pass"] = dict(persisted_adjustments.get("by_pass", {}))
        if persisted_adjustments.get("compact_by_pass"):
            section["validation_adjustment_compact_by_pass"] = dict(persisted_adjustments.get("compact_by_pass", {}))
        if persisted_adjustments.get("rows"):
            section["validation_adjustment_rows"] = list(persisted_adjustments.get("rows", []))
        if persisted_adjustments.get("compact_rows"):
            section["validation_adjustment_compact_rows"] = list(persisted_adjustments.get("compact_rows", []))
        if persisted_adjustments.get("summary"):
            section["validation_adjustment_summary"] = dict(persisted_adjustments.get("summary", {}))
        if persisted_adjustments.get("compact_summary"):
            section["validation_adjustment_compact_summary"] = dict(persisted_adjustments.get("compact_summary", {}))
        elif persisted_adjustments.get("summary"):
            section["validation_adjustment_compact_summary"] = dict(persisted_adjustments.get("summary", {}))
    elif general_degradation:
        if general_degradation.get("rows"):
            section["validation_adjustment_rows"] = list(general_degradation.get("rows", []))
        if general_degradation.get("compact_rows"):
            section["validation_adjustment_compact_rows"] = list(general_degradation.get("compact_rows", []))
        if general_degradation.get("summary"):
            section["validation_adjustment_summary"] = dict(general_degradation.get("summary", {}))
            section["validation_adjustment_compact_summary"] = dict(general_degradation.get("summary", {}))
    elif validation_adjustments:
        section["validation_adjustment_compact_summary"] = {
            "requested_validation_mode": requested_validation_mode,
            "effective_validation_mode": effective_validation_mode,
            "degraded_validation": degraded_validation,
        }
    return section
