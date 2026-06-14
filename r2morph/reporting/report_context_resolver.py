"""Context resolution helpers for report display and filtering."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_context_gate_state import _resolve_report_gate_state


def _resolve_report_context(
    *,
    payload: dict[str, Any],
    resolved_only_pass: str | None,
    resolved_only_pass_failure: str | None,
    only_expected_severity: str | None,
) -> dict[str, Any]:
    """Resolve the initial report context from payload and filters."""
    summary = payload.get("summary") or {}
    requested_validation_mode = summary.get(
        "requested_validation_mode",
        payload.get("requested_validation_mode", payload.get("validation_mode", "off")),
    )
    effective_validation_mode = summary.get(
        "validation_mode",
        payload.get("validation_mode", "off"),
    )
    validation_policy = payload.get("validation_policy")
    gate_evaluation = payload.get("gate_evaluation") or {}
    gate_requested = dict(gate_evaluation.get("requested", {}))
    gate_results = dict(gate_evaluation.get("results", {}))
    gate_failure_summary, gate_failure_priority, gate_failure_severity_priority, filtered_gate_failed = (
        _resolve_report_gate_state(
            summary=summary,
            payload=payload,
            gate_evaluation=gate_evaluation,
            only_expected_severity=only_expected_severity,
            resolved_only_pass_failure=resolved_only_pass_failure,
        )
    )
    failed_gates = bool(gate_results) and not bool(gate_results.get("all_passed", True))
    if (only_expected_severity or resolved_only_pass_failure) and not gate_failure_summary.get(
        "require_pass_severity_failure_count", 0
    ):
        failed_gates = False
    if only_expected_severity or resolved_only_pass_failure:
        failed_gates = filtered_gate_failed
    degraded_validation = requested_validation_mode != effective_validation_mode
    degraded_passes = list((validation_policy or {}).get("limited_passes", []))
    degradation_roles = dict(summary.get("degradation_roles", {}))
    return {
        "summary": summary,
        "resolved_only_pass": resolved_only_pass,
        "resolved_only_pass_failure": resolved_only_pass_failure,
        "requested_validation_mode": requested_validation_mode,
        "effective_validation_mode": effective_validation_mode,
        "validation_policy": validation_policy,
        "gate_evaluation": gate_evaluation,
        "gate_requested": gate_requested,
        "gate_results": gate_results,
        "gate_failure_summary": gate_failure_summary,
        "gate_failure_priority": gate_failure_priority,
        "gate_failure_severity_priority": gate_failure_severity_priority,
        "failed_gates": failed_gates,
        "degraded_validation": degraded_validation,
        "degraded_passes": degraded_passes,
        "degradation_roles": degradation_roles,
    }
