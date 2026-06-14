"""Report orchestration: dispatch between general and mismatch-specific report flows."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_context import ReportFlowContext
from r2morph.reporting.report_flow_executor import (
    _execute_general_report_flow,
    _execute_only_mismatches_report_flow,
)
from r2morph.reporting.report_orchestrator_context import build_report_flow_context
from r2morph.reporting.report_rendering_sections import _render_report_filter_messages
from r2morph.reporting.report_resolver import _resolve_only_mismatches_state


def _dispatch_report_flow_ctx(ctx: ReportFlowContext) -> None:
    """Dispatch between general and mismatch-specific report flows."""
    _render_report_filter_messages(
        only_pass=ctx.filters.only_pass,
        resolved_only_pass=ctx.severity.resolved_only_pass,
        only_pass_failure=ctx.filters.only_pass_failure,
        resolved_only_pass_failure=ctx.severity.resolved_only_pass_failure,
        only_risky_passes=ctx.filters.only_risky_passes,
        only_uncovered_passes=ctx.filters.only_uncovered_passes,
        only_covered_passes=ctx.filters.only_covered_passes,
        only_clean_passes=ctx.filters.only_clean_passes,
        only_structural_risk=ctx.filters.only_structural_risk,
        only_symbolic_risk=ctx.filters.only_symbolic_risk,
        selected_risk_pass_names=ctx.severity.selected_risk_pass_names,
    )
    if ctx.filters.only_mismatches:
        mismatch_state = _resolve_only_mismatches_state(
            summary=ctx.data.summary,
            mutations=ctx.data.mutations,
            filtered_summary=ctx.data.filtered_summary,
            resolved_only_pass=ctx.severity.resolved_only_pass,
            degraded_passes=ctx.validation.degraded_passes,
        )
        _execute_only_mismatches_report_flow(
            payload=ctx.data.payload,
            summary=ctx.data.summary,
            filtered_summary=ctx.data.filtered_summary,
            mismatch_state=mismatch_state,
            pass_support=ctx.data.pass_support,
            requested_validation_mode=ctx.validation.requested_validation_mode or "",
            effective_validation_mode=ctx.validation.effective_validation_mode or "",
            degraded_validation=ctx.validation.degraded_validation,
            degraded_passes=ctx.validation.degraded_passes,
            degradation_roles=ctx.validation.degradation_roles,
            failed_gates=ctx.gates.failed_gates,
            gate_evaluation=ctx.gates.gate_evaluation,
            gate_failure_summary=ctx.gates.gate_failure_summary,
            gate_failure_priority=ctx.gates.gate_failure_priority,
            gate_failure_severity_priority=ctx.gates.gate_failure_severity_priority,
            min_severity=ctx.severity.min_severity,
            only_expected_severity=ctx.filters.only_expected_severity,
            resolved_only_pass_failure=ctx.severity.resolved_only_pass_failure,
            validation_policy=ctx.validation.validation_policy,
            resolved_only_pass=ctx.severity.resolved_only_pass,
            only_status=ctx.filters.only_status,
            only_degraded=ctx.filters.only_degraded,
            only_failed_gates=ctx.filters.only_failed_gates,
            only_risky_passes=ctx.filters.only_risky_passes,
            only_uncovered_passes=ctx.filters.only_uncovered_passes,
            only_covered_passes=ctx.filters.only_covered_passes,
            only_clean_passes=ctx.filters.only_clean_passes,
            only_structural_risk=ctx.filters.only_structural_risk,
            only_symbolic_risk=ctx.filters.only_symbolic_risk,
            output=ctx.output.output,
            summary_only=ctx.output.summary_only,
            require_results=ctx.output.require_results,
            min_severity_rank=ctx.severity.min_severity_rank,
        )
        return

    _execute_general_report_flow(
        payload=ctx.data.payload,
        filtered_summary=ctx.data.filtered_summary,
        mutations=ctx.data.mutations,
        summary=ctx.data.summary,
        pass_results=ctx.data.pass_results,
        symbolic_state=ctx.data.symbolic_state,
        degraded_passes=ctx.validation.degraded_passes,
        requested_validation_mode=ctx.validation.requested_validation_mode,
        effective_validation_mode=ctx.validation.effective_validation_mode,
        degraded_validation=ctx.validation.degraded_validation,
        validation_policy=ctx.validation.validation_policy,
        gate_evaluation=ctx.gates.gate_evaluation,
        gate_requested=ctx.gates.gate_requested,
        gate_results=ctx.gates.gate_results,
        gate_failure_summary=ctx.gates.gate_failure_summary,
        gate_failure_priority=ctx.gates.gate_failure_priority,
        gate_failure_severity_priority=ctx.gates.gate_failure_severity_priority,
        degradation_roles=ctx.validation.degradation_roles,
        resolved_only_pass=ctx.severity.resolved_only_pass,
        only_status=ctx.filters.only_status,
        only_degraded=ctx.filters.only_degraded,
        only_failed_gates=ctx.filters.only_failed_gates,
        only_risky_passes=ctx.filters.only_risky_passes,
        only_uncovered_passes=ctx.filters.only_uncovered_passes,
        only_covered_passes=ctx.filters.only_covered_passes,
        only_clean_passes=ctx.filters.only_clean_passes,
        only_structural_risk=ctx.filters.only_structural_risk,
        only_symbolic_risk=ctx.filters.only_symbolic_risk,
        min_severity=ctx.severity.min_severity,
        only_expected_severity=ctx.filters.only_expected_severity,
        resolved_only_pass_failure=ctx.severity.resolved_only_pass_failure,
        output=ctx.output.output,
        summary_only=ctx.output.summary_only,
        require_results=ctx.output.require_results,
        min_severity_rank=ctx.severity.min_severity_rank,
        failed_gates=ctx.gates.failed_gates,
    )


def _dispatch_report_flow(**kwargs: Any) -> None:
    """Backward-compatible wrapper that constructs ReportFlowContext from kwargs."""
    ctx = build_report_flow_context(**kwargs)
    _dispatch_report_flow_ctx(ctx)
