"""Mismatch-view assembly for report views."""

from __future__ import annotations

from typing import Any


def build_mismatch_views(
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
