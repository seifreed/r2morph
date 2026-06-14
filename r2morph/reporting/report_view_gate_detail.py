"""Gate-failure detail assembly for report views."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_view_projections import _build_category_views


def build_gate_detail(
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_summary: dict[str, Any] | None,
    gate_failure_severity_priority: list[dict[str, Any]],
    failed_gates_rows: list[dict[str, Any]],
    failed_gates_by_pass: dict[str, dict[str, Any]],
    failed_gates_expected_severity: dict[str, Any],
) -> dict[str, Any]:
    """Build the only_failed_gates detail section."""
    gfs = gate_failure_summary or {}
    return {
        "priority": failed_gates_rows,
        "by_pass": failed_gates_by_pass,
        **_build_category_views(
            failed_gates_rows,
            compact_fields=["pass_name", "failure_count", "strictest_expected_severity", "role", "failed"],
            final_fields=["pass_name", "failure_count", "strictest_expected_severity", "role", "failed", "failures"],
        ),
        "grouped_by_pass": failed_gates_rows,
        "summary": dict(gfs),
        "severity_priority": [dict(row) for row in gate_failure_severity_priority],
        "expected_severity_counts": failed_gates_expected_severity,
        "failed": bool(gfs.get("require_pass_severity_failed")),
        "failure_count": int(gfs.get("require_pass_severity_failure_count", 0)),
        "pass_count": len(failed_gates_rows),
        "passes": [str(row.get("pass_name")) for row in failed_gates_rows if row.get("pass_name")],
        "compact_summary": {
            "failed": bool(gfs.get("require_pass_severity_failed")),
            "failure_count": int(gfs.get("require_pass_severity_failure_count", 0)),
            "pass_count": len(failed_gates_rows),
            "expected_severity_counts": failed_gates_expected_severity,
            "severity_priority": [dict(row) for row in gate_failure_severity_priority],
            "passes": [str(row.get("pass_name")) for row in failed_gates_rows if row.get("pass_name")],
        },
    }
