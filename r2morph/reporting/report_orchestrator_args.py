"""Argument assembly helpers for report orchestration."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_context import ReportFlowContext


def build_only_mismatches_report_flow_args(ctx: ReportFlowContext) -> dict[str, Any]:
    """Build keyword arguments for the only-mismatches report flow."""
    mismatch_state = _build_mismatch_state(ctx)
    return {
        "payload": ctx.data.payload,
        "summary": ctx.data.summary,
        "filtered_summary": ctx.data.filtered_summary,
        "mismatch_state": mismatch_state,
        "pass_support": ctx.data.pass_support,
        "requested_validation_mode": ctx.validation.requested_validation_mode or "",
        "effective_validation_mode": ctx.validation.effective_validation_mode or "",
        "degraded_validation": ctx.validation.degraded_validation,
        "degraded_passes": ctx.validation.degraded_passes,
        "degradation_roles": ctx.validation.degradation_roles,
        "failed_gates": ctx.gates.failed_gates,
        "gate_evaluation": ctx.gates.gate_evaluation,
        "gate_failure_summary": ctx.gates.gate_failure_summary,
        "gate_failure_priority": ctx.gates.gate_failure_priority,
        "gate_failure_severity_priority": ctx.gates.gate_failure_severity_priority,
        "min_severity": ctx.severity.min_severity,
        "only_expected_severity": ctx.filters.only_expected_severity,
        "resolved_only_pass_failure": ctx.severity.resolved_only_pass_failure,
        "validation_policy": ctx.validation.validation_policy,
        "resolved_only_pass": ctx.severity.resolved_only_pass,
        "only_status": ctx.filters.only_status,
        "only_degraded": ctx.filters.only_degraded,
        "only_failed_gates": ctx.filters.only_failed_gates,
        "only_risky_passes": ctx.filters.only_risky_passes,
        "only_uncovered_passes": ctx.filters.only_uncovered_passes,
        "only_covered_passes": ctx.filters.only_covered_passes,
        "only_clean_passes": ctx.filters.only_clean_passes,
        "only_structural_risk": ctx.filters.only_structural_risk,
        "only_symbolic_risk": ctx.filters.only_symbolic_risk,
        "output": ctx.output.output,
        "summary_only": ctx.output.summary_only,
        "require_results": ctx.output.require_results,
        "min_severity_rank": ctx.severity.min_severity_rank,
    }


def build_general_report_flow_args(ctx: ReportFlowContext) -> dict[str, Any]:
    """Build keyword arguments for the general report flow."""
    return {
        "payload": ctx.data.payload,
        "filtered_summary": ctx.data.filtered_summary,
        "mutations": ctx.data.mutations,
        "summary": ctx.data.summary,
        "pass_results": ctx.data.pass_results,
        "symbolic_state": ctx.data.symbolic_state,
        "degraded_passes": ctx.validation.degraded_passes,
        "requested_validation_mode": ctx.validation.requested_validation_mode,
        "effective_validation_mode": ctx.validation.effective_validation_mode,
        "degraded_validation": ctx.validation.degraded_validation,
        "validation_policy": ctx.validation.validation_policy,
        "gate_evaluation": ctx.gates.gate_evaluation,
        "gate_requested": ctx.gates.gate_requested,
        "gate_results": ctx.gates.gate_results,
        "gate_failure_summary": ctx.gates.gate_failure_summary,
        "gate_failure_priority": ctx.gates.gate_failure_priority,
        "gate_failure_severity_priority": ctx.gates.gate_failure_severity_priority,
        "degradation_roles": ctx.validation.degradation_roles,
        "resolved_only_pass": ctx.severity.resolved_only_pass,
        "only_status": ctx.filters.only_status,
        "only_degraded": ctx.filters.only_degraded,
        "only_failed_gates": ctx.filters.only_failed_gates,
        "only_risky_passes": ctx.filters.only_risky_passes,
        "only_uncovered_passes": ctx.filters.only_uncovered_passes,
        "only_covered_passes": ctx.filters.only_covered_passes,
        "only_clean_passes": ctx.filters.only_clean_passes,
        "only_structural_risk": ctx.filters.only_structural_risk,
        "only_symbolic_risk": ctx.filters.only_symbolic_risk,
        "min_severity": ctx.severity.min_severity,
        "only_expected_severity": ctx.filters.only_expected_severity,
        "resolved_only_pass_failure": ctx.severity.resolved_only_pass_failure,
        "output": ctx.output.output,
        "summary_only": ctx.output.summary_only,
        "require_results": ctx.output.require_results,
        "min_severity_rank": ctx.severity.min_severity_rank,
        "failed_gates": ctx.gates.failed_gates,
    }


def _build_mismatch_state(ctx: ReportFlowContext) -> dict[str, Any]:
    from r2morph.reporting.report_resolver import _resolve_only_mismatches_state

    return _resolve_only_mismatches_state(
        summary=ctx.data.summary,
        mutations=ctx.data.mutations,
        filtered_summary=ctx.data.filtered_summary,
        resolved_only_pass=ctx.severity.resolved_only_pass,
        degraded_passes=ctx.validation.degraded_passes,
    )
