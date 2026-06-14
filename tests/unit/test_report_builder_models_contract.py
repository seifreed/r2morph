"""Contract tests for report builder model dataclasses."""

from __future__ import annotations

from r2morph.reporting.report_builder_models import FilteredReport, ReportContext


def test_report_builder_models_contract() -> None:
    context = ReportContext(
        summary={"total": 1},
        resolved_only_pass="pass-a",
        resolved_only_pass_failure=None,
        requested_validation_mode="symbolic",
        effective_validation_mode="symbolic",
        validation_policy={"limited_passes": []},
        gate_evaluation={},
        gate_requested={},
        gate_results={},
        gate_failure_summary={},
        gate_failure_priority=[],
        gate_failure_severity_priority=[],
        failed_gates=False,
        degraded_validation=False,
        degraded_passes=[],
        degradation_roles={},
    )
    report = FilteredReport(
        payload={"mutations": []},
        filtered_mutations=[],
        filtered_summary={"mutations": 0},
        gate_evaluation={},
        gate_failures={},
        gate_failure_priority=[],
        gate_failure_severity_priority=[],
        report_filters={"only_pass": "pass-a"},
    )

    assert context.summary == {"total": 1}
    assert report.filtered_summary["mutations"] == 0
