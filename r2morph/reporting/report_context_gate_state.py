"""Gate-state resolution helpers for report context filtering."""

from __future__ import annotations

import re
from typing import Any

from r2morph.reporting.gate_evaluator import (
    build_gate_failure_severity_priority as _build_gate_failure_severity_priority,
)
from r2morph.reporting.gate_evaluator import (
    summarize_gate_failures as _summarize_gate_failures,
)
from r2morph.reporting.report_gate_filters import (
    _expected_severity_rank_from_failure,
    _filter_failed_gates_view,
)


def _resolve_failed_gates_view(
    *,
    summary: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve failed-gates summary and ordering from persisted report views first."""
    report_views = dict(summary.get("report_views", {}) or {})
    failed_gates_view = dict(report_views.get("only_failed_gates", {}) or {})
    persisted_summary = dict(failed_gates_view.get("summary", {}) or {})
    persisted_priority = list(failed_gates_view.get("priority", []) or [])
    persisted_severity_priority = list(failed_gates_view.get("severity_priority", []) or [])
    if persisted_summary:
        gate_failure_summary = persisted_summary
    if persisted_priority:
        gate_failure_priority = persisted_priority
    if persisted_severity_priority:
        gate_failure_severity_priority = persisted_severity_priority
    if not gate_failure_severity_priority:
        gate_failure_severity_priority = _build_gate_failure_severity_priority(gate_failure_summary)
    return gate_failure_summary, gate_failure_priority, gate_failure_severity_priority


def _resolve_report_gate_state(
    *,
    summary: dict[str, Any],
    payload: dict[str, Any],
    gate_evaluation: dict[str, Any],
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Resolve persisted gate summaries and filtered gate state for report()."""
    gate_failure_summary = _summarize_gate_failures(gate_evaluation) if gate_evaluation else {}
    gate_failure_priority = list(summary.get("gate_failure_priority", payload.get("gate_failure_priority", [])))
    gate_failure_severity_priority = list(
        summary.get(
            "gate_failure_severity_priority",
            payload.get("gate_failure_severity_priority", []),
        )
    )
    gate_failure_summary, gate_failure_priority, gate_failure_severity_priority = _resolve_failed_gates_view(
        summary=summary,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
    )
    if gate_failure_summary.get("require_pass_severity_failures_by_pass"):
        ordered_failures = sorted(
            gate_failure_summary["require_pass_severity_failures_by_pass"].items(),
            key=lambda item: (
                min(_expected_severity_rank_from_failure(failure) for failure in item[1]),
                -len(item[1]),
                item[0],
            ),
        )
        gate_failure_summary["require_pass_severity_failures_by_pass"] = {
            pass_name: failures for pass_name, failures in ordered_failures
        }
    if not gate_failure_priority:
        gate_failure_priority = [
            {
                "pass_name": pass_name,
                "failure_count": len(failures),
                "strictest_expected_severity": (
                    min(
                        (
                            severity
                            for severity in (re.search(r"expected <= ([^)]+)", failure) for failure in failures)
                            if severity
                        ),
                        key=lambda match: _expected_severity_rank_from_failure(f"expected <= {match.group(1)}"),
                    ).group(1)
                    if failures
                    else "unknown"
                ),
                "failures": list(failures),
            }
            for pass_name, failures in gate_failure_summary.get("require_pass_severity_failures_by_pass", {}).items()
        ]
    gate_failure_summary, gate_failure_priority, gate_failure_severity_priority, filtered_gate_failed = (
        _filter_failed_gates_view(
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            only_expected_severity=only_expected_severity,
            resolved_only_pass_failure=resolved_only_pass_failure,
        )
    )
    return (
        gate_failure_summary,
        gate_failure_priority,
        gate_failure_severity_priority,
        filtered_gate_failed,
    )
