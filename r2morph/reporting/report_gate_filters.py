"""Gate filtering helpers for reporting."""

from __future__ import annotations

from typing import Any

from r2morph.core.constants import SEVERITY_ORDER as CORE_SEVERITY_ORDER
from r2morph.reporting.gate_evaluator import (
    build_gate_failure_severity_priority as _build_gate_failure_severity_priority,
)
from r2morph.reporting.report_severity_parsing import (
    _expected_severity_rank_from_failure as _expected_severity_rank_from_failure,
)

SEVERITY_ORDER = CORE_SEVERITY_ORDER


def _filter_failed_gates_view(
    *,
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Apply gate filters to the normalized failed-gates view."""
    filtered_summary = dict(gate_failure_summary)
    filtered_priority = list(gate_failure_priority)
    filtered_severity_priority = list(gate_failure_severity_priority)
    if only_expected_severity:
        filtered_severity_priority = [
            row for row in filtered_severity_priority if row.get("severity") == only_expected_severity
        ]
        filtered_priority = [
            row for row in filtered_priority if row.get("strictest_expected_severity") == only_expected_severity
        ]
        filtered_summary["require_pass_severity_failures_by_expected_severity"] = {
            row.get("severity", "unknown"): row.get("failure_count", 0) for row in filtered_severity_priority
        }
    if resolved_only_pass_failure:
        filtered_priority = [row for row in filtered_priority if row.get("pass_name") == resolved_only_pass_failure]
    filtered_summary["require_pass_severity_failures_by_pass"] = {
        row.get("pass_name", "unknown"): list(row.get("failures", [])) for row in filtered_priority
    }
    filtered_summary["require_pass_severity_failures"] = [
        failure for row in filtered_priority for failure in row.get("failures", [])
    ]
    filtered_summary["require_pass_severity_failure_count"] = len(filtered_summary["require_pass_severity_failures"])
    filtered_summary["require_pass_severity_failed"] = bool(filtered_summary["require_pass_severity_failures"])
    if resolved_only_pass_failure:
        severity_counts: dict[str, int] = {}
        for row in filtered_priority:
            severity = row.get("strictest_expected_severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + int(row.get("failure_count", 0))
        filtered_summary["require_pass_severity_failures_by_expected_severity"] = severity_counts
        filtered_severity_priority = _build_gate_failure_severity_priority(filtered_summary)
    filtered_failed = bool(filtered_summary.get("require_pass_severity_failure_count", 0))
    return filtered_summary, filtered_priority, filtered_severity_priority, filtered_failed
