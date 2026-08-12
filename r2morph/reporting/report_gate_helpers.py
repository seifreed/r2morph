"""Gate evaluation helpers for reporting.

This module owns the report gate policy and filtering helpers that were
previously mixed into the broader report helper module.
"""

from __future__ import annotations

from typing import Any

from r2morph.reporting.gate_evaluator import GateEvaluationRequest, GateEvaluator


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
    request: GateEvaluationRequest,
) -> dict[str, Any]:
    """Attach CLI gate evaluation metadata to a report payload."""
    return GateEvaluator.attach_gate_evaluation(report_payload, request)
