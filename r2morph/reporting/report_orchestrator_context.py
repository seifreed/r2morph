"""Report flow context construction helpers."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_context import (
    FilterFlags,
    GateState,
    OutputConfig,
    ReportFlowContext,
    ReportPayload,
    SeverityFilter,
    ValidationState,
)


def build_report_flow_context(**kwargs: Any) -> ReportFlowContext:
    """Backward-compatible builder for ReportFlowContext from legacy kwargs."""
    return ReportFlowContext(
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


__all__ = ["build_report_flow_context"]
