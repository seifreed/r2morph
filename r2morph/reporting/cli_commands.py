"""Report command handler for the CLI."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from r2morph.cli_workflow_validation import resolve_min_severity
from r2morph.cli_workflows import _resolve_report_pass_filter
from r2morph.reporting.report_command_io import emit_report_output, load_report_payload
from r2morph.reporting.report_context import (
    FilterFlags,
    GateState,
    OutputConfig,
    PassClassFilters,
    ReportFlowContext,
    ReportPayload,
    SeverityFilter,
    ValidationState,
)
from r2morph.reporting.report_context_resolver import _resolve_report_context as _resolve_report_context_impl
from r2morph.reporting.report_orchestrator import _dispatch_report_flow_ctx
from r2morph.reporting.report_resolver import _resolve_general_report_flow_state


@dataclass(frozen=True)
class ReportCommandOptions:
    only_pass: str | None = None
    only_status: str | None = None
    only_mismatches: bool = False
    summary_only: bool = False
    output: Path | None = None
    require_results: bool = False
    min_severity: str | None = None
    only_expected_severity: str | None = None
    only_pass_failure: str | None = None
    only_degraded: bool = False
    only_failed_gates: bool = False
    pass_classes: PassClassFilters = field(default_factory=PassClassFilters)
    output_format: str = "json"


def handle_report_command(report_file: Path, options: ReportCommandOptions) -> dict[str, Any]:
    """Handle the report command."""
    only_pass = options.only_pass
    only_status = options.only_status
    only_mismatches = options.only_mismatches
    summary_only = options.summary_only
    output = options.output
    require_results = options.require_results
    min_severity = options.min_severity
    only_expected_severity = options.only_expected_severity
    only_pass_failure = options.only_pass_failure
    only_degraded = options.only_degraded
    only_failed_gates = options.only_failed_gates
    pass_classes = options.pass_classes
    output_format = options.output_format
    payload = load_report_payload(report_file)

    resolved_only_pass = _resolve_report_pass_filter(only_pass)
    resolved_only_pass_failure = _resolve_report_pass_filter(only_pass_failure)
    _, min_severity_rank = resolve_min_severity(min_severity)

    return_payload: dict[str, Any] = dict(payload)
    if resolved_only_pass:
        mutations = [m for m in payload.get("mutations", []) if m.get("pass_name") == resolved_only_pass]
        return_payload["mutations"] = mutations
        return_payload["filtered_summary"] = {
            "passes": [resolved_only_pass] if mutations else [],
            "mutations": len(mutations),
        }

    context = _resolve_report_context_impl(
        payload=payload,
        resolved_only_pass=resolved_only_pass,
        resolved_only_pass_failure=resolved_only_pass_failure,
        only_expected_severity=only_expected_severity,
    )
    summary = context.summary
    requested_validation_mode = context.requested_validation_mode
    effective_validation_mode = context.effective_validation_mode
    validation_policy = context.validation_policy
    gate_evaluation = context.gate_evaluation
    gate_failure_summary = context.gate_failure_summary
    gate_failure_priority = context.gate_failure_priority
    gate_failure_severity_priority = context.gate_failure_severity_priority
    failed_gates = context.failed_gates
    degraded_validation = context.degraded_validation
    pass_results = payload.get("passes", {})
    general_state = _resolve_general_report_flow_state(
        payload,
        pass_results,
        context,
        FilterFlags(
            only_status=only_status,
            only_degraded=only_degraded,
            only_failed_gates=only_failed_gates,
            only_risky_passes=pass_classes.only_risky_passes,
            only_structural_risk=pass_classes.only_structural_risk,
            only_symbolic_risk=pass_classes.only_symbolic_risk,
            only_uncovered_passes=pass_classes.only_uncovered_passes,
            only_covered_passes=pass_classes.only_covered_passes,
            only_clean_passes=pass_classes.only_clean_passes,
        ),
    )

    report_context = ReportFlowContext(
        data=ReportPayload(
            payload=payload,
            summary=summary,
            filtered_summary=general_state["filtered_summary"],
            mutations=general_state["mutations"],
            pass_results=pass_results,
            pass_support=general_state["pass_support"],
            symbolic_state=general_state["symbolic_state"],
        ),
        validation=ValidationState(
            requested_validation_mode=requested_validation_mode,
            effective_validation_mode=effective_validation_mode,
            degraded_validation=degraded_validation,
            degraded_passes=general_state["degraded_passes"],
            degradation_roles=general_state["degradation_roles"],
            validation_policy=validation_policy,
        ),
        gates=GateState(
            failed_gates=failed_gates,
            gate_evaluation=gate_evaluation,
            gate_requested=context.gate_requested,
            gate_results=context.gate_results,
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
        ),
        filters=FilterFlags(
            only_mismatches=only_mismatches,
            only_status=only_status,
            only_degraded=only_degraded,
            only_failed_gates=only_failed_gates,
            only_risky_passes=pass_classes.only_risky_passes,
            only_structural_risk=pass_classes.only_structural_risk,
            only_symbolic_risk=pass_classes.only_symbolic_risk,
            only_uncovered_passes=pass_classes.only_uncovered_passes,
            only_covered_passes=pass_classes.only_covered_passes,
            only_clean_passes=pass_classes.only_clean_passes,
            only_pass=only_pass,
            only_pass_failure=only_pass_failure,
            only_expected_severity=only_expected_severity,
        ),
        severity=SeverityFilter(
            min_severity=min_severity,
            min_severity_rank=min_severity_rank,
            resolved_only_pass=resolved_only_pass,
            resolved_only_pass_failure=resolved_only_pass_failure,
            selected_risk_pass_names=general_state["selected_risk_pass_names"],
        ),
        output=OutputConfig(
            output=output,
            summary_only=summary_only,
            require_results=require_results,
        ),
    )

    if require_results:
        filtered_mutations = return_payload.get("mutations", payload.get("mutations", []))
        if isinstance(filtered_mutations, list):
            return_payload["mutations"] = filtered_mutations
        return_payload["filtered_summary"] = report_context.data.filtered_summary

    if output_format.lower() == "sarif":
        emit_report_output(
            output_format=output_format,
            output=output,
            mutations=payload.get("mutations", []),
            validations=payload.get("validations", []),
            binary_path=payload.get("binary_path", ""),
        )
        return return_payload

    _dispatch_report_flow_ctx(report_context)
    return return_payload


__all__ = ["ReportCommandOptions", "handle_report_command"]
