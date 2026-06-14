from r2morph.reporting.report_context import (
    FilterFlags,
    GateState,
    OutputConfig,
    ReportFlowContext,
    ReportPayload,
    SeverityFilter,
    ValidationState,
)
from r2morph.reporting.report_orchestrator_args import (
    build_general_report_flow_args,
    build_only_mismatches_report_flow_args,
)


def test_report_orchestrator_args_contract() -> None:
    ctx = ReportFlowContext(
        data=ReportPayload(payload={"mutations": []}, summary={"total": 1}, filtered_summary={"mutations": 0}),
        validation=ValidationState(
            requested_validation_mode="symbolic",
            effective_validation_mode="symbolic",
            degraded_validation=False,
            degraded_passes=[],
            degradation_roles={},
            validation_policy={"mode": "symbolic"},
        ),
        gates=GateState(
            failed_gates=False,
            gate_evaluation={},
            gate_requested={},
            gate_results={},
            gate_failure_summary={},
            gate_failure_priority=[],
            gate_failure_severity_priority=[],
        ),
        filters=FilterFlags(only_mismatches=True, only_status="degraded"),
        severity=SeverityFilter(
            min_severity="medium",
            min_severity_rank=2,
            resolved_only_pass="pass-a",
            resolved_only_pass_failure=None,
            selected_risk_pass_names={"pass-a"},
        ),
        output=OutputConfig(output=None, summary_only=False, require_results=False),
    )

    general_args = build_general_report_flow_args(ctx)
    mismatch_args = build_only_mismatches_report_flow_args(ctx)

    assert general_args["summary"]["total"] == 1
    assert general_args["failed_gates"] is False
    assert mismatch_args["resolved_only_pass"] == "pass-a"
    assert mismatch_args["mismatch_state"]["filtered_mutations"] == []
