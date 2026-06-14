"""Gate-view assembly for report views."""

from __future__ import annotations

from typing import Any

from r2morph.core.report_helpers_indexing import _index_rows_by_pass_name


def build_gate_views(
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
    failed_gates_by_pass = _index_rows_by_pass_name(failed_gates_rows)
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
