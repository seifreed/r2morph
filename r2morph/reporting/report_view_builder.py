"""
Report view builder extracted from engine.py.

Contains the _build_report_views() function that transforms raw mutation
and validation results into structured report views.
"""

from typing import Any

from r2morph.reporting.gate_evaluator import SEVERITY_ORDER


def _build_report_views(
    *,
    pass_risk_buckets: dict[str, list[str]],
    pass_coverage_buckets: dict[str, list[str]],
    pass_triage_rows: list[dict[str, Any]],
    normalized_pass_results: list[dict[str, Any]],
    pass_symbolic_summary: dict[str, Any],
    pass_evidence_map: dict[str, Any],
    pass_region_evidence_map: dict[str, list[dict[str, Any]]],
    pass_validation_context: dict[str, Any],
    pass_capability_summary_map: dict[str, Any],
    observable_mismatch_priority: list[dict[str, Any]],
    observable_mismatch_map: dict[str, dict[str, Any]],
    symbolic_severity_by_pass: list[dict[str, Any]],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_summary: dict[str, Any] | None,
    gate_failure_severity_priority: list[dict[str, Any]],
    discarded_mutation_priority: list[dict[str, Any]],
    discarded_mutation_summary: dict[str, Any],
    validation_adjustment_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Persist small precomputed views for common report filters."""
    normalized_pass_map = {
        str(row.get("pass_name")): dict(row) for row in normalized_pass_results if row.get("pass_name")
    }
    triage_priority = [
        dict(row)
        for row in sorted(
            (row for row in pass_triage_rows if row.get("pass_name")),
            key=lambda row: (
                int(row.get("severity_order", 99)),
                -int(row.get("structural_issue_count", 0)),
                -int(row.get("symbolic_binary_mismatched_regions", 0)),
                str(row.get("pass_name", "")),
            ),
        )
    ]
    symbolic_severity_map = {
        str(row.get("pass_name")): dict(row) for row in symbolic_severity_by_pass if row.get("pass_name")
    }
    discarded_by_pass = {
        str(row.get("pass_name")): dict(row)
        for row in list(discarded_mutation_summary.get("by_pass", []) or [])
        if row.get("pass_name")
    }
    base_general_pass_rows = [
        {
            **dict(row),
            "region_evidence_count": len(pass_region_evidence_map.get(str(row.get("pass_name", "")), [])),
        }
        for row in normalized_pass_results
        if row.get("pass_name")
    ]
    mismatch_rows = []
    for row in observable_mismatch_priority:
        pass_name = str(row.get("pass_name", ""))
        if not pass_name:
            continue
        normalized_row = normalized_pass_map.get(pass_name, {})
        severity_row = symbolic_severity_map.get(pass_name, {})
        validation_context = pass_validation_context.get(pass_name, {})
        region_evidence = list(pass_region_evidence_map.get(pass_name, []))
        mismatch_rows.append(
            {
                "pass_name": pass_name,
                "mismatch_count": int(row.get("mismatch_count", 0)),
                "observables": list(row.get("observables", [])),
                "severity": severity_row.get("severity", "mismatch"),
                "issue_count": int(severity_row.get("issue_count", 0)),
                "symbolic_requested": int(severity_row.get("symbolic_requested", 0)),
                "role": normalized_row.get("role", "requested-mode"),
                "symbolic_confidence": normalized_row.get("symbolic_confidence", "unknown"),
                "degraded_execution": bool(validation_context.get("degraded_execution", False)),
                "degradation_triggered_by_pass": bool(validation_context.get("degradation_triggered_by_pass", False)),
                "region_evidence": region_evidence,
                "region_count": len(region_evidence),
                "region_mismatch_count": sum(int(item.get("mismatch_count", 0)) for item in region_evidence),
                "region_exit_match_count": sum(1 for item in region_evidence if item.get("region_exit_equivalent")),
                "compact_region": {
                    "region_count": len(region_evidence),
                    "region_mismatch_count": sum(int(item.get("mismatch_count", 0)) for item in region_evidence),
                    "region_exit_match_count": sum(1 for item in region_evidence if item.get("region_exit_equivalent")),
                },
            }
        )
    mismatch_by_pass = {}
    for row in mismatch_rows:
        pass_name = str(row.get("pass_name", ""))
        if not pass_name:
            continue
        mismatch_by_pass[pass_name] = {
            "pass_name": pass_name,
            "mismatch_count": int(row.get("mismatch_count", 0)),
            "observables": list(row.get("observables", [])),
            "severity": row.get("severity", "mismatch"),
            "issue_count": int(row.get("issue_count", 0)),
            "symbolic_requested": int(row.get("symbolic_requested", 0)),
            "role": row.get("role", "requested-mode"),
            "symbolic_confidence": row.get("symbolic_confidence", "unknown"),
            "degraded_execution": bool(row.get("degraded_execution", False)),
            "degradation_triggered_by_pass": bool(row.get("degradation_triggered_by_pass", False)),
            "region_evidence": list(row.get("region_evidence", [])),
            "region_count": int(row.get("region_count", 0)),
            "region_mismatch_count": int(row.get("region_mismatch_count", 0)),
            "region_exit_match_count": int(row.get("region_exit_match_count", 0)),
            "compact_region": dict(row.get("compact_region", {})),
        }
    only_pass = {}
    for row in triage_priority:
        pass_name = str(row.get("pass_name", ""))
        if not pass_name:
            continue
        only_pass[pass_name] = {
            "normalized": dict(normalized_pass_map.get(pass_name, row)),
            "symbolic_summary": dict(pass_symbolic_summary.get(pass_name, {})),
            "evidence": dict(pass_evidence_map.get(pass_name, {})),
            "region_evidence": list(pass_region_evidence_map.get(pass_name, [])),
            "validation_context": dict(pass_validation_context.get(pass_name, {})),
            "capabilities": dict(pass_capability_summary_map.get(pass_name, {})),
        }
    failed_gates_rows = [
        {
            "pass_name": row.get("pass_name"),
            "failure_count": int(row.get("failure_count", 0)),
            "strictest_expected_severity": row.get("strictest_expected_severity", "unknown"),
            "failures": list(row.get("failures", [])),
            "role": normalized_pass_map.get(str(row.get("pass_name", "")), {}).get("role", "requested-mode"),
        }
        for row in gate_failure_priority
        if row.get("pass_name")
    ]
    failed_gates_compact_rows = [
        {
            "pass_name": str(row.get("pass_name")),
            "failure_count": int(row.get("failure_count", 0)),
            "strictest_expected_severity": row.get("strictest_expected_severity", "unknown"),
            "role": row.get("role", "requested-mode"),
            "failed": bool(row.get("failures")),
        }
        for row in failed_gates_rows
        if row.get("pass_name")
    ]
    failed_gates_final_rows = [
        {
            "pass_name": str(row.get("pass_name")),
            "failure_count": int(row.get("failure_count", 0)),
            "strictest_expected_severity": row.get("strictest_expected_severity", "unknown"),
            "role": row.get("role", "requested-mode"),
            "failed": bool(row.get("failures")),
            "failures": list(row.get("failures", [])),
        }
        for row in failed_gates_rows
        if row.get("pass_name")
    ]
    failed_gates_by_pass = {str(row.get("pass_name")): dict(row) for row in failed_gates_rows if row.get("pass_name")}
    general_pass_row_map = {}
    for row in base_general_pass_rows:
        pass_name = str(row.get("pass_name", ""))
        if not pass_name:
            continue
        validation_context = dict(pass_validation_context.get(pass_name, {}) or {})
        discarded_row = dict(discarded_by_pass.get(pass_name, {}) or {})
        gate_row = dict(failed_gates_by_pass.get(pass_name, {}) or {})
        general_pass_row_map[pass_name] = {
            **dict(row),
            "degraded_execution": bool(validation_context.get("degraded_execution", False)),
            "degradation_triggered_by_pass": bool(validation_context.get("degradation_triggered_by_pass", False)),
            "gate_failure_count": int(gate_row.get("failure_count", 0)),
            "strictest_expected_severity": gate_row.get("strictest_expected_severity", "unknown"),
            "discarded_count": int(discarded_row.get("discarded_count", 0)),
            "discard_reasons": dict(discarded_row.get("reasons", {}) or {}),
            "discard_impacts": dict(discarded_row.get("impact_counts", {}) or {}),
        }
    general_pass_rows = [general_pass_row_map[pass_name] for pass_name in sorted(general_pass_row_map)]
    failed_gates_expected_severity = dict(
        (gate_failure_summary or {}).get("require_pass_severity_failures_by_expected_severity", {})
    )
    degraded_rows = [
        dict(row)
        for row in validation_adjustment_rows
        if row.get("degraded_validation")
        or row.get("triggered_adjustment")
        or row.get("executed_under_degraded_mode")
        or row.get("gate_failure_count", 0)
    ]
    general_symbolic = {
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
    general_gates = {
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
    general_degradation = {
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
    general_discards = {
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
        "filter_views": {
            "risky": list(pass_risk_buckets.get("risky", [])),
            "structural_risk": list(pass_risk_buckets.get("structural", [])),
            "symbolic_risk": list(pass_risk_buckets.get("symbolic", [])),
            "clean": list(pass_risk_buckets.get("clean", [])),
            "covered": list(pass_coverage_buckets.get("covered", [])),
            "uncovered": list(pass_coverage_buckets.get("uncovered", [])),
        },
        "passes": [dict(row) for row in general_pass_rows],
        "general_passes": [dict(row) for row in general_pass_rows],
        "general_filter_views": {
            "risky": list(pass_risk_buckets.get("risky", [])),
            "structural_risk": list(pass_risk_buckets.get("structural", [])),
            "symbolic_risk": list(pass_risk_buckets.get("symbolic", [])),
            "clean": list(pass_risk_buckets.get("clean", [])),
            "covered": list(pass_coverage_buckets.get("covered", [])),
            "uncovered": list(pass_coverage_buckets.get("uncovered", [])),
        },
        "pass_rows": [dict(row) for row in general_pass_rows],
        "general_pass_rows": [dict(row) for row in general_pass_rows],
        "triage_rows": [dict(row) for row in triage_priority],
        "general_triage_rows": [dict(row) for row in triage_priority],
    }
    return {
        "general_passes": general_pass_rows,
        "general_pass_rows": general_pass_rows,
        "general_summary": general_summary_payload,
        "general_summary_rows": general_summary_rows,
        "general_renderer_state": general_renderer_state,
        "general_triage_rows": [dict(row) for row in triage_priority],
        "general_filter_views": {
            "risky": list(pass_risk_buckets.get("risky", [])),
            "structural_risk": list(pass_risk_buckets.get("structural", [])),
            "symbolic_risk": list(pass_risk_buckets.get("symbolic", [])),
            "clean": list(pass_risk_buckets.get("clean", [])),
            "covered": list(pass_coverage_buckets.get("covered", [])),
            "uncovered": list(pass_coverage_buckets.get("uncovered", [])),
        },
        "general_symbolic": general_symbolic,
        "general_gates": general_gates,
        "general_degradation": general_degradation,
        "general_discards": general_discards,
        "passes": {
            "risky": list(pass_risk_buckets.get("risky", [])),
            "structural_risk": list(pass_risk_buckets.get("structural", [])),
            "symbolic_risk": list(pass_risk_buckets.get("symbolic", [])),
            "clean": list(pass_risk_buckets.get("clean", [])),
            "covered": list(pass_coverage_buckets.get("covered", [])),
            "uncovered": list(pass_coverage_buckets.get("uncovered", [])),
        },
        "triage_priority": triage_priority,
        "only_pass": only_pass,
        "pass_filter_views": {
            "only_risky_passes": list(pass_risk_buckets.get("risky", [])),
            "only_structural_risk": list(pass_risk_buckets.get("structural", [])),
            "only_symbolic_risk": list(pass_risk_buckets.get("symbolic", [])),
            "only_clean_passes": list(pass_risk_buckets.get("clean", [])),
            "only_covered_passes": list(pass_coverage_buckets.get("covered", [])),
            "only_uncovered_passes": list(pass_coverage_buckets.get("uncovered", [])),
        },
        "mismatch_priority": [dict(row) for row in observable_mismatch_priority],
        "mismatch_map": {str(pass_name): dict(row) for pass_name, row in observable_mismatch_map.items()},
        "mismatch_view": mismatch_rows,
        "only_mismatches": {
            "priority": [dict(row) for row in observable_mismatch_priority],
            "by_pass": mismatch_by_pass,
            "compact_by_pass": {
                str(row.get("pass_name", "")): {
                    "pass_name": str(row.get("pass_name", "")),
                    "mismatch_count": int(row.get("mismatch_count", 0)),
                    "severity": row.get("severity", "mismatch"),
                    "role": row.get("role", "requested-mode"),
                    "symbolic_confidence": row.get("symbolic_confidence", "unknown"),
                    "degraded_execution": bool(row.get("degraded_execution", False)),
                    "region_count": int(row.get("region_count", 0)),
                    "region_mismatch_count": int(row.get("region_mismatch_count", 0)),
                    "region_exit_match_count": int(row.get("region_exit_match_count", 0)),
                    "compact_region": dict(row.get("compact_region", {})),
                }
                for row in mismatch_rows
                if row.get("pass_name")
            },
            "rows": mismatch_rows,
            "compact_rows": [
                {
                    "pass_name": str(row.get("pass_name", "")),
                    "mismatch_count": int(row.get("mismatch_count", 0)),
                    "severity": row.get("severity", "mismatch"),
                    "role": row.get("role", "requested-mode"),
                    "symbolic_confidence": row.get("symbolic_confidence", "unknown"),
                    "degraded_execution": bool(row.get("degraded_execution", False)),
                    "region_count": int(row.get("region_count", 0)),
                    "region_mismatch_count": int(row.get("region_mismatch_count", 0)),
                    "region_exit_match_count": int(row.get("region_exit_match_count", 0)),
                    "compact_region": dict(row.get("compact_region", {})),
                }
                for row in mismatch_rows
            ],
            "final_rows": [
                {
                    "pass_name": str(row.get("pass_name", "")),
                    "mismatch_count": int(row.get("mismatch_count", 0)),
                    "severity": row.get("severity", "mismatch"),
                    "role": row.get("role", "requested-mode"),
                    "symbolic_confidence": row.get("symbolic_confidence", "unknown"),
                    "degraded_execution": bool(row.get("degraded_execution", False)),
                    "region_count": int(row.get("region_count", 0)),
                    "region_mismatch_count": int(row.get("region_mismatch_count", 0)),
                    "region_exit_match_count": int(row.get("region_exit_match_count", 0)),
                    "compact_region": dict(row.get("compact_region", {})),
                }
                for row in mismatch_rows
            ],
            "final_by_pass": {
                str(row.get("pass_name", "")): {
                    "pass_name": str(row.get("pass_name", "")),
                    "mismatch_count": int(row.get("mismatch_count", 0)),
                    "severity": row.get("severity", "mismatch"),
                    "role": row.get("role", "requested-mode"),
                    "symbolic_confidence": row.get("symbolic_confidence", "unknown"),
                    "degraded_execution": bool(row.get("degraded_execution", False)),
                    "region_count": int(row.get("region_count", 0)),
                    "region_mismatch_count": int(row.get("region_mismatch_count", 0)),
                    "region_exit_match_count": int(row.get("region_exit_match_count", 0)),
                    "compact_region": dict(row.get("compact_region", {})),
                }
                for row in mismatch_rows
                if row.get("pass_name")
            },
            "compact_summary": {
                "pass_count": len(mismatch_rows),
                "mismatch_count": sum(int(row.get("mismatch_count", 0)) for row in mismatch_rows),
                "degraded_pass_count": sum(1 for row in mismatch_rows if row.get("degraded_execution")),
                "region_count": sum(int(row.get("region_count", 0)) for row in mismatch_rows),
                "region_mismatch_count": sum(int(row.get("region_mismatch_count", 0)) for row in mismatch_rows),
                "region_exit_match_count": sum(int(row.get("region_exit_match_count", 0)) for row in mismatch_rows),
                "passes": [str(row.get("pass_name")) for row in mismatch_rows if row.get("pass_name")],
            },
            "summary": {
                "pass_count": len(mismatch_rows),
                "mismatch_count": sum(int(row.get("mismatch_count", 0)) for row in mismatch_rows),
                "degraded_pass_count": sum(1 for row in mismatch_rows if row.get("degraded_execution")),
                "trigger_pass_count": sum(1 for row in mismatch_rows if row.get("degradation_triggered_by_pass")),
                "region_count": sum(int(row.get("region_count", 0)) for row in mismatch_rows),
                "region_mismatch_count": sum(int(row.get("region_mismatch_count", 0)) for row in mismatch_rows),
                "region_exit_match_count": sum(int(row.get("region_exit_match_count", 0)) for row in mismatch_rows),
                "passes": [str(row.get("pass_name")) for row in mismatch_rows if row.get("pass_name")],
            },
        },
        "failed_gates": [dict(row) for row in gate_failure_priority],
        "only_failed_gates": {
            "priority": failed_gates_rows,
            "by_pass": failed_gates_by_pass,
            "compact_by_pass": {
                str(row.get("pass_name")): {
                    "pass_name": str(row.get("pass_name")),
                    "failure_count": int(row.get("failure_count", 0)),
                    "strictest_expected_severity": row.get("strictest_expected_severity", "unknown"),
                    "role": row.get("role", "requested-mode"),
                    "failed": bool(row.get("failures")),
                }
                for row in failed_gates_rows
                if row.get("pass_name")
            },
            "grouped_by_pass": failed_gates_rows,
            "compact_rows": failed_gates_compact_rows,
            "final_rows": failed_gates_final_rows,
            "final_by_pass": {
                str(row.get("pass_name")): {
                    "pass_name": str(row.get("pass_name")),
                    "failure_count": int(row.get("failure_count", 0)),
                    "strictest_expected_severity": row.get("strictest_expected_severity", "unknown"),
                    "role": row.get("role", "requested-mode"),
                    "failed": bool(row.get("failures")),
                    "failures": list(row.get("failures", [])),
                }
                for row in failed_gates_rows
                if row.get("pass_name")
            },
            "summary": dict(gate_failure_summary or {}),
            "severity_priority": [dict(row) for row in gate_failure_severity_priority],
            "expected_severity_counts": failed_gates_expected_severity,
            "failed": bool((gate_failure_summary or {}).get("require_pass_severity_failed")),
            "failure_count": int((gate_failure_summary or {}).get("require_pass_severity_failure_count", 0)),
            "pass_count": len(failed_gates_rows),
            "passes": [str(row.get("pass_name")) for row in failed_gates_rows if row.get("pass_name")],
            "compact_summary": {
                "failed": bool((gate_failure_summary or {}).get("require_pass_severity_failed")),
                "failure_count": int((gate_failure_summary or {}).get("require_pass_severity_failure_count", 0)),
                "pass_count": len(failed_gates_rows),
                "expected_severity_counts": failed_gates_expected_severity,
                "severity_priority": [dict(row) for row in gate_failure_severity_priority],
                "passes": [str(row.get("pass_name")) for row in failed_gates_rows if row.get("pass_name")],
            },
        },
        "validation_adjustments": {
            "rows": degraded_rows,
            "by_pass": {str(row.get("pass_name")): dict(row) for row in degraded_rows if row.get("pass_name")},
            "compact_by_pass": {
                str(row.get("pass_name")): {
                    "pass_name": str(row.get("pass_name")),
                    "role": row.get("role", "requested-mode"),
                    "triggered_adjustment": bool(row.get("triggered_adjustment")),
                    "executed_under_degraded_mode": bool(row.get("executed_under_degraded_mode")),
                    "gate_failure_count": int(row.get("gate_failure_count", 0)),
                }
                for row in degraded_rows
                if row.get("pass_name")
            },
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
            "summary": {
                "requested_validation_mode": next(
                    (
                        row.get("requested_validation_mode")
                        for row in degraded_rows
                        if row.get("requested_validation_mode")
                    ),
                    None,
                ),
                "effective_validation_mode": next(
                    (
                        row.get("effective_validation_mode")
                        for row in degraded_rows
                        if row.get("effective_validation_mode")
                    ),
                    None,
                ),
                "row_count": len(degraded_rows),
                "trigger_count": sum(1 for row in degraded_rows if row.get("triggered_adjustment")),
                "degraded_execution_count": sum(1 for row in degraded_rows if row.get("executed_under_degraded_mode")),
                "degraded_validation": bool(degraded_rows),
                "gate_failure_count": sum(int(row.get("gate_failure_count", 0)) for row in degraded_rows),
                "passes": [str(row.get("pass_name")) for row in degraded_rows if row.get("pass_name")],
            },
            "compact_summary": {
                "degraded_validation": bool(degraded_rows),
                "row_count": len(degraded_rows),
                "trigger_count": sum(1 for row in degraded_rows if row.get("triggered_adjustment")),
                "degraded_execution_count": sum(1 for row in degraded_rows if row.get("executed_under_degraded_mode")),
                "gate_failure_count": sum(int(row.get("gate_failure_count", 0)) for row in degraded_rows),
                "passes": [str(row.get("pass_name")) for row in degraded_rows if row.get("pass_name")],
            },
        },
        "discarded_view": {
            "priority": [dict(row) for row in discarded_mutation_priority],
            "rows": [dict(row) for row in discarded_mutation_priority],
            "compact_by_pass": {
                str(row.get("pass_name", "unknown")): {
                    "pass_name": str(row.get("pass_name", "unknown")),
                    "discarded_count": int(row.get("discarded_count", 0)),
                    "impact_severity": row.get("impact_severity", "low"),
                    "reason_count": len(list(row.get("reasons", []))),
                }
                for row in discarded_mutation_priority
                if row.get("pass_name")
            },
            "compact_rows": [
                {
                    "pass_name": str(row.get("pass_name", "unknown")),
                    "discarded_count": int(row.get("discarded_count", 0)),
                    "impact_severity": row.get("impact_severity", "low"),
                    "reason_count": len(list(row.get("reasons", []))),
                }
                for row in discarded_mutation_priority
            ],
            "final_rows": [
                {
                    "pass_name": str(row.get("pass_name", "unknown")),
                    "discarded_count": int(row.get("discarded_count", 0)),
                    "impact_severity": row.get("impact_severity", "low"),
                    "reason_count": len(list(row.get("reasons", []))),
                    "reasons": list(row.get("reasons", [])),
                }
                for row in discarded_mutation_priority
            ],
            "final_by_pass": {
                str(row.get("pass_name", "unknown")): {
                    "pass_name": str(row.get("pass_name", "unknown")),
                    "discarded_count": int(row.get("discarded_count", 0)),
                    "impact_severity": row.get("impact_severity", "low"),
                    "reason_count": len(list(row.get("reasons", []))),
                    "reasons": list(row.get("reasons", [])),
                }
                for row in discarded_mutation_priority
                if row.get("pass_name")
            },
            "by_reason": dict(discarded_mutation_summary.get("by_reason", {})),
            "compact_by_reason": {
                str(reason): int(count)
                for reason, count in discarded_mutation_summary.get("by_reason", {}).items()
                if count
            },
            "by_pass": [dict(row) for row in discarded_mutation_summary.get("by_pass", [])],
            "by_impact": dict(discarded_mutation_summary.get("by_impact", {})),
            "summary": {
                "count": len(discarded_mutation_priority),
                "passes": [str(row.get("pass_name")) for row in discarded_mutation_priority if row.get("pass_name")],
                "reasons": sorted(
                    str(reason) for reason, count in discarded_mutation_summary.get("by_reason", {}).items() if count
                ),
                "impacts": {
                    str(level): len(rows) for level, rows in discarded_mutation_summary.get("by_impact", {}).items()
                },
            },
            "compact_summary": {
                "count": len(discarded_mutation_priority),
                "pass_count": len([row for row in discarded_mutation_priority if row.get("pass_name")]),
                "reason_count": len(
                    [reason for reason, count in discarded_mutation_summary.get("by_reason", {}).items() if count]
                ),
                "impact_counts": {
                    str(level): len(rows) for level, rows in discarded_mutation_summary.get("by_impact", {}).items()
                },
                "passes": [str(row.get("pass_name")) for row in discarded_mutation_priority if row.get("pass_name")],
            },
        },
    }
