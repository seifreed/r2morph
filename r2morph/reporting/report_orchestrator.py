"""Report orchestration: dispatch between general and mismatch-specific report flows."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_context import ReportFlowContext
from r2morph.reporting.report_flow_executor import (
    _execute_general_report_flow,
    _execute_only_mismatches_report_flow,
)
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
    from r2morph.reporting.report_context import (
        FilterFlags,
        GateState,
        OutputConfig,
        ReportFlowContext,
        ReportPayload,
        SeverityFilter,
        ValidationState,
    )

    ctx = ReportFlowContext(
        data=ReportPayload(
            payload=kwargs.get("payload", {}),
            summary=kwargs.get("summary", {}),
            filtered_summary=kwargs.get("filtered_summary", {}),
            mutations=kwargs.get("mutations", []),
            pass_results=kwargs.get("pass_results", {}),
            pass_support=kwargs.get("pass_support", {}),
            symbolic_state=kwargs.get("symbolic_state", {}),
        ),
        validation=ValidationState(
            requested_validation_mode=kwargs.get("requested_validation_mode"),
            effective_validation_mode=kwargs.get("effective_validation_mode"),
            degraded_validation=kwargs.get("degraded_validation", False),
            degraded_passes=kwargs.get("degraded_passes", []),
            degradation_roles=kwargs.get("degradation_roles", {}),
            validation_policy=kwargs.get("validation_policy"),
        ),
        gates=GateState(
            failed_gates=kwargs.get("failed_gates", False),
            gate_evaluation=kwargs.get("gate_evaluation", {}),
            gate_requested=kwargs.get("gate_requested", {}),
            gate_results=kwargs.get("gate_results", {}),
            gate_failure_summary=kwargs.get("gate_failure_summary", {}),
            gate_failure_priority=kwargs.get("gate_failure_priority", []),
            gate_failure_severity_priority=kwargs.get("gate_failure_severity_priority", []),
        ),
        filters=FilterFlags(
            only_mismatches=kwargs.get("only_mismatches", False),
            only_status=kwargs.get("only_status"),
            only_degraded=kwargs.get("only_degraded", False),
            only_failed_gates=kwargs.get("only_failed_gates", False),
            only_risky_passes=kwargs.get("only_risky_passes", False),
            only_structural_risk=kwargs.get("only_structural_risk", False),
            only_symbolic_risk=kwargs.get("only_symbolic_risk", False),
            only_uncovered_passes=kwargs.get("only_uncovered_passes", False),
            only_covered_passes=kwargs.get("only_covered_passes", False),
            only_clean_passes=kwargs.get("only_clean_passes", False),
            only_pass=kwargs.get("only_pass"),
            only_pass_failure=kwargs.get("only_pass_failure"),
            only_expected_severity=kwargs.get("only_expected_severity"),
        ),
        severity=SeverityFilter(
            min_severity=kwargs.get("min_severity"),
            min_severity_rank=kwargs.get("min_severity_rank"),
            resolved_only_pass=kwargs.get("resolved_only_pass"),
            resolved_only_pass_failure=kwargs.get("resolved_only_pass_failure"),
            selected_risk_pass_names=kwargs.get("selected_risk_pass_names", set()),
        ),
        output=OutputConfig(
            output=kwargs.get("output"),
            summary_only=kwargs.get("summary_only", False),
            require_results=kwargs.get("require_results", False),
        ),
    )
    _dispatch_report_flow_ctx(ctx)
