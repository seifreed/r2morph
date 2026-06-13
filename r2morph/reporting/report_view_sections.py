"""Section builders for report view assembly."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_context import ReportViews
from r2morph.reporting.report_view_details import _assemble_report_views
from r2morph.reporting.report_view_projections import _build_lookup_maps
from r2morph.reporting.report_view_summary import _build_summary_views


def _build_pass_views(
    *,
    normalized_pass_results: list[dict[str, Any]],
    pass_region_evidence_map: dict[str, list[dict[str, Any]]],
    pass_validation_context: dict[str, Any],
    pass_symbolic_summary: dict[str, Any],
    pass_evidence_map: dict[str, Any],
    pass_capability_summary_map: dict[str, Any],
    normalized_pass_map: dict[str, dict[str, Any]],
    triage_priority: list[dict[str, Any]],
    discarded_by_pass: dict[str, dict[str, Any]],
    failed_gates_by_pass: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build base_general_pass_rows, general_pass_row_map, general_pass_rows, only_pass."""
    base_general_pass_rows = [
        {
            **dict(row),
            "region_evidence_count": len(pass_region_evidence_map.get(str(row.get("pass_name", "")), [])),
        }
        for row in normalized_pass_results
        if row.get("pass_name")
    ]
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
    return {
        "base_general_pass_rows": base_general_pass_rows,
        "general_pass_row_map": general_pass_row_map,
        "general_pass_rows": general_pass_rows,
        "only_pass": only_pass,
    }


def _build_mismatch_views(
    *,
    observable_mismatch_priority: list[dict[str, Any]],
    normalized_pass_map: dict[str, dict[str, Any]],
    symbolic_severity_map: dict[str, dict[str, Any]],
    pass_validation_context: dict[str, Any],
    pass_region_evidence_map: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """Build mismatch_rows, mismatch_by_pass."""
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
    mismatch_by_pass = {str(row["pass_name"]): dict(row) for row in mismatch_rows if row.get("pass_name")}
    return {
        "mismatch_rows": mismatch_rows,
        "mismatch_by_pass": mismatch_by_pass,
    }


def _build_gate_views(
    *,
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_summary: dict[str, Any] | None,
    gate_failure_severity_priority: list[dict[str, Any]],
    normalized_pass_map: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build failed_gates_rows, failed_gates_compact_rows, failed_gates_final_rows, failed_gates_by_pass."""
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
    failed_gates_expected_severity = dict(
        (gate_failure_summary or {}).get("require_pass_severity_failures_by_expected_severity", {})
    )
    return {
        "failed_gates_rows": failed_gates_rows,
        "failed_gates_compact_rows": failed_gates_compact_rows,
        "failed_gates_final_rows": failed_gates_final_rows,
        "failed_gates_by_pass": failed_gates_by_pass,
        "failed_gates_expected_severity": failed_gates_expected_severity,
    }


def build_report_views(
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
) -> ReportViews:
    """Persist small precomputed views for common report filters."""
    lookups = _build_lookup_maps(
        normalized_pass_results=normalized_pass_results,
        pass_triage_rows=pass_triage_rows,
        symbolic_severity_by_pass=symbolic_severity_by_pass,
        discarded_mutation_summary=discarded_mutation_summary,
    )
    normalized_pass_map = lookups["normalized_pass_map"]
    triage_priority = lookups["triage_priority"]
    symbolic_severity_map = lookups["symbolic_severity_map"]
    discarded_by_pass = lookups["discarded_by_pass"]

    gates = _build_gate_views(
        gate_failure_priority=gate_failure_priority,
        gate_failure_summary=gate_failure_summary,
        gate_failure_severity_priority=gate_failure_severity_priority,
        normalized_pass_map=normalized_pass_map,
    )
    failed_gates_rows = gates["failed_gates_rows"]
    failed_gates_by_pass = gates["failed_gates_by_pass"]
    failed_gates_expected_severity = gates["failed_gates_expected_severity"]

    passes = _build_pass_views(
        normalized_pass_results=normalized_pass_results,
        pass_region_evidence_map=pass_region_evidence_map,
        pass_validation_context=pass_validation_context,
        pass_symbolic_summary=pass_symbolic_summary,
        pass_evidence_map=pass_evidence_map,
        pass_capability_summary_map=pass_capability_summary_map,
        normalized_pass_map=normalized_pass_map,
        triage_priority=triage_priority,
        discarded_by_pass=discarded_by_pass,
        failed_gates_by_pass=failed_gates_by_pass,
    )
    general_pass_rows = passes["general_pass_rows"]
    only_pass = passes["only_pass"]

    mismatches = _build_mismatch_views(
        observable_mismatch_priority=observable_mismatch_priority,
        normalized_pass_map=normalized_pass_map,
        symbolic_severity_map=symbolic_severity_map,
        pass_validation_context=pass_validation_context,
        pass_region_evidence_map=pass_region_evidence_map,
    )
    mismatch_rows = mismatches["mismatch_rows"]
    mismatch_by_pass = mismatches["mismatch_by_pass"]

    filter_buckets = {
        "risky": list(pass_risk_buckets.get("risky", [])),
        "structural_risk": list(pass_risk_buckets.get("structural", [])),
        "symbolic_risk": list(pass_risk_buckets.get("symbolic", [])),
        "clean": list(pass_risk_buckets.get("clean", [])),
        "covered": list(pass_coverage_buckets.get("covered", [])),
        "uncovered": list(pass_coverage_buckets.get("uncovered", [])),
    }

    summary = _build_summary_views(
        normalized_pass_results=normalized_pass_results,
        symbolic_severity_by_pass=symbolic_severity_by_pass,
        gate_failure_priority=gate_failure_priority,
        gate_failure_summary=gate_failure_summary,
        gate_failure_severity_priority=gate_failure_severity_priority,
        discarded_mutation_priority=discarded_mutation_priority,
        discarded_mutation_summary=discarded_mutation_summary,
        validation_adjustment_rows=validation_adjustment_rows,
        pass_risk_buckets=pass_risk_buckets,
        pass_coverage_buckets=pass_coverage_buckets,
        triage_priority=triage_priority,
        general_pass_rows=general_pass_rows,
        failed_gates_rows=failed_gates_rows,
        failed_gates_expected_severity=failed_gates_expected_severity,
        filter_buckets=filter_buckets,
    )
    degraded_rows = summary["degraded_rows"]
    general_symbolic = summary["general_symbolic"]
    general_gates = summary["general_gates"]
    general_degradation = summary["general_degradation"]
    general_discards = summary["general_discards"]
    general_summary_payload = summary["general_summary_payload"]
    general_summary_rows = summary["general_summary_rows"]
    general_renderer_state = summary["general_renderer_state"]

    return _assemble_report_views(
        general_pass_rows=general_pass_rows,
        general_summary_payload=general_summary_payload,
        general_summary_rows=general_summary_rows,
        general_renderer_state=general_renderer_state,
        triage_priority=triage_priority,
        filter_buckets=filter_buckets,
        general_symbolic=general_symbolic,
        general_gates=general_gates,
        general_degradation=general_degradation,
        general_discards=general_discards,
        only_pass=only_pass,
        observable_mismatch_priority=observable_mismatch_priority,
        observable_mismatch_map=observable_mismatch_map,
        mismatch_rows=mismatch_rows,
        mismatch_by_pass=mismatch_by_pass,
        gate_failure_priority=gate_failure_priority,
        gate_failure_summary=gate_failure_summary,
        gate_failure_severity_priority=gate_failure_severity_priority,
        failed_gates_rows=failed_gates_rows,
        failed_gates_by_pass=failed_gates_by_pass,
        failed_gates_expected_severity=failed_gates_expected_severity,
        degraded_rows=degraded_rows,
        discarded_mutation_priority=discarded_mutation_priority,
        discarded_mutation_summary=discarded_mutation_summary,
    )
