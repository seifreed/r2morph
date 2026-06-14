"""Triage-oriented report helpers extracted from core.report_helpers."""

from __future__ import annotations

from typing import Any

from r2morph.core.constants import SEVERITY_ORDER, UNKNOWN_SEVERITY_RANK
from r2morph.core.report_helpers_indexing import _index_rows_by_pass_name


def _summarize_pass_triage_rows(
    pass_results: dict[str, Any],
    pass_capability_summary_map: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build one compact triage row per pass for CLI/report consumers."""
    severity_order = SEVERITY_ORDER
    rows = []
    for pass_name, pass_result in pass_results.items():
        symbolic_summary = dict(pass_result.get("symbolic_summary", {}) or {})
        evidence_summary = dict(pass_result.get("evidence_summary", {}) or {})
        validation_context = dict(pass_result.get("validation_context", {}) or {})
        capability_summary = dict(pass_capability_summary_map.get(pass_name, {}) or {})
        severity = symbolic_summary.get("severity", "not-requested")
        rows.append(
            {
                "pass_name": pass_name,
                "severity": severity,
                "severity_order": severity_order.get(severity, UNKNOWN_SEVERITY_RANK),
                "issue_count": int(symbolic_summary.get("issue_count", 0)),
                "symbolic_requested": int(symbolic_summary.get("symbolic_requested", 0)),
                "observable_match": int(symbolic_summary.get("observable_match", 0)),
                "observable_mismatch": int(symbolic_summary.get("observable_mismatch", 0)),
                "bounded_only": int(symbolic_summary.get("bounded_only", 0)),
                "without_coverage": int(symbolic_summary.get("without_coverage", 0)),
                "structural_issue_count": int(evidence_summary.get("structural_issue_count", 0)),
                "symbolic_binary_mismatched_regions": int(
                    evidence_summary.get("symbolic_binary_mismatched_regions", 0)
                ),
                "changed_region_count": int(evidence_summary.get("changed_region_count", 0)),
                "changed_bytes": int(evidence_summary.get("changed_bytes", 0)),
                "role": validation_context.get("role", "requested-mode"),
                "degraded_execution": bool(validation_context.get("degraded_execution", False)),
                "runtime_recommended": bool(capability_summary.get("runtime_recommended", False)),
                "symbolic_recommended": bool(capability_summary.get("symbolic_recommended", False)),
                "symbolic_confidence": capability_summary.get("symbolic_confidence", "unknown"),
            }
        )
    rows.sort(
        key=lambda item: (
            severity_order.get(item["severity"], UNKNOWN_SEVERITY_RANK),
            -item["symbolic_binary_mismatched_regions"],
            -item["structural_issue_count"],
            -item["changed_region_count"],
            item["pass_name"],
        )
    )
    return rows


def _summarize_pass_evidence_compact(
    pass_triage_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build a compact evidence/triage view ready for rendering."""
    rows = [
        {
            "pass_name": row.get("pass_name"),
            "severity": row.get("severity", "unknown"),
            "structural_issue_count": row.get("structural_issue_count", 0),
            "symbolic_binary_mismatched_regions": row.get("symbolic_binary_mismatched_regions", 0),
            "changed_region_count": row.get("changed_region_count", 0),
            "changed_bytes": row.get("changed_bytes", 0),
            "role": row.get("role", "unknown"),
            "symbolic_confidence": row.get("symbolic_confidence", "unknown"),
        }
        for row in pass_triage_rows
        if row.get("pass_name")
    ]
    return rows


def _build_pass_triage_map(
    rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Index triage rows by pass name."""
    return _index_rows_by_pass_name(rows)
