"""Gate evaluation helpers for reporting.

This module owns the report gate policy and filtering helpers that were
previously mixed into the broader report helper module.
"""

from __future__ import annotations

from typing import Any

from r2morph.reporting.gate_evaluator import (
    build_gate_failure_priority as _build_gate_failure_priority,
)
from r2morph.reporting.gate_evaluator import (
    build_gate_failure_severity_priority as _build_gate_failure_severity_priority,
)
from r2morph.reporting.gate_evaluator import (
    summarize_gate_failures as _summarize_gate_failures,
)
from r2morph.reporting.report_gate_severity_policy import (
    _pass_severity_requirements_met as _pass_severity_requirements_met,
)
from r2morph.reporting.report_gate_severity_policy import (
    _severity_threshold_met as _severity_threshold_met,
)


def _gate_failure_result_count(gate_failures: dict[str, Any]) -> int:
    """Return a non-zero count when any persisted gate failure is present."""
    count = int(gate_failures.get("require_pass_severity_failure_count", 0) or 0)
    if gate_failures.get("min_severity_failed"):
        count += 1
    if gate_failures.get("all_passed") is False and count == 0:
        count = 1
    return count


def _attach_gate_evaluation(
    report_payload: dict[str, Any],
    *,
    min_severity: str | None,
    min_severity_passed: bool,
    require_pass_severity: list[tuple[str, str, int]],
    require_pass_severity_passed: bool,
    require_pass_severity_failures: list[str],
) -> dict[str, Any]:
    """Attach CLI gate evaluation metadata to a report payload."""
    gate_evaluation = {
        "requested": {
            "min_severity": min_severity,
            "require_pass_severity": [
                {"pass_name": pass_name, "max_severity": severity}
                for pass_name, severity, _rank in require_pass_severity
            ],
        },
        "results": {
            "min_severity_passed": min_severity_passed,
            "require_pass_severity_passed": require_pass_severity_passed,
            "require_pass_severity_failures": list(require_pass_severity_failures),
            "all_passed": min_severity_passed and require_pass_severity_passed,
        },
    }
    gate_failures = _summarize_gate_failures(gate_evaluation)
    gate_failure_priority = _build_gate_failure_priority(gate_failures)
    gate_failure_severity_priority = _build_gate_failure_severity_priority(gate_failures)
    report_payload["gate_evaluation"] = gate_evaluation
    report_payload["gate_failures"] = gate_failures
    report_payload["gate_failure_priority"] = gate_failure_priority
    report_payload["gate_failure_severity_priority"] = gate_failure_severity_priority
    summary: dict[str, Any] = dict(report_payload.get("summary", {}) or {})
    summary["gate_evaluation"] = gate_evaluation["results"]
    summary["gate_failures"] = gate_failures
    summary["gate_failure_priority"] = gate_failure_priority
    summary["gate_failure_severity_priority"] = gate_failure_severity_priority
    report_payload["summary"] = summary
    return report_payload
