"""Pass-view assembly for report views."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_context import ReportViewInputs


def build_pass_views(
    inputs: ReportViewInputs,
    lookups: dict[str, Any],
    gates: dict[str, Any],
) -> dict[str, Any]:
    """Build base_general_pass_rows, general_pass_row_map, general_pass_rows, only_pass."""
    normalized_pass_map = lookups["normalized_pass_map"]
    triage_priority = lookups["triage_priority"]
    discarded_by_pass = lookups["discarded_by_pass"]
    failed_gates_by_pass = gates["failed_gates_by_pass"]
    base_general_pass_rows = [
        {
            **dict(row),
            "region_evidence_count": len(inputs.pass_region_evidence_map.get(str(row.get("pass_name", "")), [])),
        }
        for row in inputs.normalized_pass_results
        if row.get("pass_name")
    ]
    only_pass = {}
    for row in triage_priority:
        pass_name = str(row.get("pass_name", ""))
        if not pass_name:
            continue
        only_pass[pass_name] = {
            "normalized": dict(normalized_pass_map.get(pass_name, row)),
            "symbolic_summary": dict(inputs.pass_symbolic_summary.get(pass_name, {})),
            "evidence": dict(inputs.pass_evidence_map.get(pass_name, {})),
            "region_evidence": list(inputs.pass_region_evidence_map.get(pass_name, [])),
            "validation_context": dict(inputs.pass_validation_context.get(pass_name, {})),
            "capabilities": dict(inputs.pass_capability_summary_map.get(pass_name, {})),
        }
    general_pass_row_map = {}
    for row in base_general_pass_rows:
        pass_name = str(row.get("pass_name", ""))
        if not pass_name:
            continue
        validation_context = dict(inputs.pass_validation_context.get(pass_name, {}) or {})
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
