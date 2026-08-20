"""Contract tests for report builder model dataclasses."""

from __future__ import annotations

from r2morph.reporting.report_builder_models import FilteredReport, ReportContext
from tests.utils.assertions import expect
from tests.utils.field_names import RESOLVED_ONLY_FAILED_MUTATION_KEY, RESOLVED_ONLY_MUTATION_KEY


def test_report_builder_models_contract() -> None:
    context = ReportContext(
        summary={"total": 1},
        **{RESOLVED_ONLY_MUTATION_KEY: "pass-a"},
        **{RESOLVED_ONLY_FAILED_MUTATION_KEY: None},
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

    expect(context.summary == {"total": 1})
    expect(report.filtered_summary["mutations"] == 0)
