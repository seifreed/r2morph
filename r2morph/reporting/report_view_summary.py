"""Summary view shaping helpers for report view assembly."""

from __future__ import annotations

from typing import Any


def _build_summary_views(
    *,
    normalized_pass_results: list[dict[str, Any]],
    symbolic_severity_by_pass: list[dict[str, Any]],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_summary: dict[str, Any] | None,
    gate_failure_severity_priority: list[dict[str, Any]],
    discarded_mutation_priority: list[dict[str, Any]],
    discarded_mutation_summary: dict[str, Any],
    validation_adjustment_rows: list[dict[str, Any]],
    pass_risk_buckets: dict[str, list[str]],
    pass_coverage_buckets: dict[str, list[str]],
    triage_priority: list[dict[str, Any]],
    general_pass_rows: list[dict[str, Any]],
    failed_gates_rows: list[dict[str, Any]],
    failed_gates_expected_severity: dict[str, Any],
    filter_buckets: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Build general_symbolic, general_gates, general_degradation, general_discards, and renderer state."""
    degraded_rows = [
        dict(row)
        for row in validation_adjustment_rows
        if row.get("degraded_validation")
        or row.get("triggered_adjustment")
        or row.get("executed_under_degraded_mode")
        or row.get("gate_failure_count", 0)
    ]
    general_symbolic: dict[str, Any] = {
        "overview": {
            "symbolic_requested": sum(int(row.get("symbolic_requested", 0)) for row in normalized_pass_results),
            "observable_match": sum(int(row.get("observable_match", 0)) for row in normalized_pass_results),
            "observable_mismatch": sum(int(row.get("observable_mismatch", 0)) for row in normalized_pass_results),
            "bounded_only": sum(int(row.get("bounded_only", 0)) for row in normalized_pass_results),
            "without_coverage": sum(int(row.get("without_coverage", 0)) for row in normalized_pass_results),
        },
        "severity_by_pass": [dict(row) for row in symbolic_severity_by_pass],
        "triage_rows": [dict(row) for row in triage_priority],
    }
    general_gates: dict[str, Any] = {
        "summary": dict(gate_failure_summary or {}),
        "priority": [dict(row) for row in gate_failure_priority],
        "severity_priority": [dict(row) for row in gate_failure_severity_priority],
        "compact_summary": {
            "failed": bool((gate_failure_summary or {}).get("require_pass_severity_failed")),
            "failure_count": int((gate_failure_summary or {}).get("require_pass_severity_failure_count", 0)),
            "pass_count": len(failed_gates_rows),
            "expected_severity_counts": failed_gates_expected_severity,
            "severity_priority": [dict(row) for row in gate_failure_severity_priority],
            "passes": [str(row.get("pass_name")) for row in failed_gates_rows if row.get("pass_name")],
        },
    }
    general_degradation: dict[str, Any] = {
        "summary": {
            "requested_validation_mode": next(
                (row.get("requested_validation_mode") for row in degraded_rows if row.get("requested_validation_mode")),
                None,
            ),
            "effective_validation_mode": next(
                (row.get("effective_validation_mode") for row in degraded_rows if row.get("effective_validation_mode")),
                None,
            ),
            "degraded_validation": bool(degraded_rows),
            "row_count": len(degraded_rows),
            "passes": [str(row.get("pass_name")) for row in degraded_rows if row.get("pass_name")],
            "gate_failure_count": sum(int(row.get("gate_failure_count", 0)) for row in degraded_rows),
        },
        "rows": [dict(row) for row in degraded_rows],
        "compact_rows": [
            {
                "pass_name": str(row.get("pass_name", "unknown")),
                "role": row.get("role", "requested-mode"),
                "triggered_adjustment": bool(row.get("triggered_adjustment")),
                "executed_under_degraded_mode": bool(row.get("executed_under_degraded_mode")),
                "gate_failure_count": int(row.get("gate_failure_count", 0)),
            }
            for row in degraded_rows
        ],
    }
    general_discards: dict[str, Any] = {
        "summary": {
            "count": sum(int(row.get("discarded_count", 0)) for row in discarded_mutation_priority),
            "passes": [str(row.get("pass_name")) for row in discarded_mutation_priority if row.get("pass_name")],
            "reasons": dict(discarded_mutation_summary.get("by_reason", {}) or {}),
            "impacts": {
                severity: len(list((discarded_mutation_summary.get("by_impact", {}) or {}).get(severity, [])))
                for severity in ("high", "medium", "low")
            },
        },
        "rows": [dict(row) for row in discarded_mutation_priority],
    }
    general_summary_payload = {
        "pass_count": len(general_pass_rows),
        "passes": [str(row.get("pass_name")) for row in general_pass_rows if row.get("pass_name")],
        "risky_pass_count": len(pass_risk_buckets.get("risky", [])),
        "clean_pass_count": len(pass_risk_buckets.get("clean", [])),
        "covered_pass_count": len(pass_coverage_buckets.get("covered", [])),
        "uncovered_pass_count": len(pass_coverage_buckets.get("uncovered", [])),
    }
    general_summary_rows = [
        {"section": "passes", **general_summary_payload},
        {"section": "symbolic", **dict(general_symbolic.get("overview", {}))},
        {"section": "gates", **dict(general_gates.get("compact_summary", {}))},
        {"section": "degradation", **dict(general_degradation.get("summary", {}))},
        {"section": "discards", **dict(general_discards.get("summary", {}))},
    ]
    general_renderer_state = {
        "summary": dict(general_summary_payload),
        "general_summary": dict(general_summary_payload),
        "summary_rows": [dict(row) for row in general_summary_rows],
        "general_summary_rows": [dict(row) for row in general_summary_rows],
        "symbolic": dict(general_symbolic.get("overview", {})),
        "general_symbolic": dict(general_symbolic.get("overview", {})),
        "gates": dict(general_gates.get("compact_summary", {})),
        "general_gates": dict(general_gates.get("compact_summary", {})),
        "degradation": dict(general_degradation.get("summary", {})),
        "general_degradation": dict(general_degradation.get("summary", {})),
        "discards": dict(general_discards.get("summary", {})),
        "general_discards": dict(general_discards.get("summary", {})),
        "filter_views": filter_buckets or {},
        "passes": [dict(row) for row in general_pass_rows],
        "general_passes": [dict(row) for row in general_pass_rows],
        "general_filter_views": filter_buckets or {},
        "pass_rows": [dict(row) for row in general_pass_rows],
        "general_pass_rows": [dict(row) for row in general_pass_rows],
        "triage_rows": [dict(row) for row in triage_priority],
        "general_triage_rows": [dict(row) for row in triage_priority],
    }
    return {
        "degraded_rows": degraded_rows,
        "general_symbolic": general_symbolic,
        "general_gates": general_gates,
        "general_degradation": general_degradation,
        "general_discards": general_discards,
        "general_summary_payload": general_summary_payload,
        "general_summary_rows": general_summary_rows,
        "general_renderer_state": general_renderer_state,
    }
