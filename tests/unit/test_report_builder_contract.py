"""Contract tests for the report builder compatibility wrapper."""

from __future__ import annotations

from r2morph.reporting.filtered_summary_builder import _build_only_mismatches_payload as filtered_payload_impl
from r2morph.reporting.filtered_summary_builder import _build_report_filters as report_filters_impl
from r2morph.reporting.report_builder import ReportBuilder
from r2morph.reporting.report_context_resolver import _resolve_failed_gates_view as resolve_failed_gates_view_impl
from r2morph.reporting.report_context_resolver import _resolve_report_gate_state as resolve_gate_state_impl
from r2morph.reporting.report_gate_helpers import (
    _expected_severity_rank_from_failure as expected_severity_rank_impl,
)
from r2morph.reporting.report_gate_helpers import _filter_failed_gates_view as filter_failed_gates_view_impl


def test_report_builder_gate_state_delegates_to_shared_helpers() -> None:
    summary = {
        "gate_failure_priority": [{"pass_name": "p1", "failures": ["expected <= medium"]}],
        "gate_failure_severity_priority": [{"severity": "medium", "failure_count": 1}],
        "report_views": {
            "only_failed_gates": {
                "summary": {
                    "require_pass_severity_failures_by_pass": {"p1": ["expected <= medium"]},
                },
                "priority": [{"pass_name": "p1", "failures": ["expected <= medium"]}],
                "severity_priority": [{"severity": "medium", "failure_count": 1}],
            }
        },
    }
    payload = {
        "gate_failure_priority": [{"pass_name": "p1", "failures": ["expected <= medium"]}],
        "gate_failure_severity_priority": [{"severity": "medium", "failure_count": 1}],
    }
    gate_evaluation = {
        "require_pass_severity_failures": [{"pass_name": "p1", "failures": ["expected <= medium"]}]
    }

    assert (
        ReportBuilder._resolve_report_gate_state(
            summary=summary,
            payload=payload,
            gate_evaluation=gate_evaluation,
            only_expected_severity="medium",
            resolved_only_pass_failure="p1",
        )
        == resolve_gate_state_impl(
            summary=summary,
            payload=payload,
            gate_evaluation=gate_evaluation,
            only_expected_severity="medium",
            resolved_only_pass_failure="p1",
        )
    )


def test_report_builder_gate_helpers_delegate_to_shared_helpers() -> None:
    failures = ["expected <= medium", "expected <= high"]
    gate_failure_summary = {
        "require_pass_severity_failures_by_pass": {"p1": list(failures)},
        "require_pass_severity_failures": list(failures),
        "require_pass_severity_failure_count": 2,
        "require_pass_severity_failed": True,
    }
    gate_failure_priority = [
        {"pass_name": "p1", "strictest_expected_severity": "medium", "failure_count": 2, "failures": list(failures)}
    ]
    gate_failure_severity_priority = [{"severity": "medium", "failure_count": 2}]

    assert ReportBuilder._expected_severity_rank_from_failure("expected <= medium") == expected_severity_rank_impl(
        "expected <= medium"
    )
    assert (
        ReportBuilder._resolve_failed_gates_view(
            summary={},
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
        )
        == resolve_failed_gates_view_impl(
            summary={},
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
        )
    )
    assert (
        ReportBuilder._filter_failed_gates_view(
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            only_expected_severity="medium",
            resolved_only_pass_failure="p1",
        )
        == filter_failed_gates_view_impl(
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            only_expected_severity="medium",
            resolved_only_pass_failure="p1",
        )
    )


def test_report_builder_filtered_payload_helpers_delegate_to_shared_helpers() -> None:
    payload = {"summary": {"existing": True}}
    summary = {"existing": True}
    filtered_summary = {"existing": True}
    filtered_mutations = [{"id": 1}]
    filtered_passes = ["p1"]
    mismatch_counts_by_pass = {"p1": 1}
    mismatch_observables_by_pass = {"p1": ["obs"]}
    persisted_mismatch_priority = [{"pass_name": "p1"}]
    mismatch_severity_rows = [{"pass_name": "p1"}]
    mismatch_pass_context = {"p1": {"status": "ok"}}
    requested_validation_mode = "structural"
    effective_validation_mode = "structural"
    degraded_validation = False
    mismatch_degraded_passes = []
    degraded_passes = []
    degradation_roles = {}
    failed_gates = False
    pass_support = {"p1": {}}
    gate_evaluation = {"require_pass_severity_failures": []}
    gate_failure_summary = {}
    gate_failure_priority = []
    gate_failure_severity_priority = []
    min_severity = None
    only_expected_severity = None
    resolved_only_pass_failure = None
    validation_policy = None

    assert (
        ReportBuilder.build_only_mismatches_payload(
            payload=payload,
            summary=summary,
            filtered_summary=filtered_summary,
            filtered_mutations=filtered_mutations,
            filtered_passes=filtered_passes,
            mismatch_counts_by_pass=mismatch_counts_by_pass,
            mismatch_observables_by_pass=mismatch_observables_by_pass,
            persisted_mismatch_priority=persisted_mismatch_priority,
            mismatch_severity_rows=mismatch_severity_rows,
            mismatch_pass_context=mismatch_pass_context,
            requested_validation_mode=requested_validation_mode,
            effective_validation_mode=effective_validation_mode,
            degraded_validation=degraded_validation,
            mismatch_degraded_passes=mismatch_degraded_passes,
            degraded_passes=degraded_passes,
            degradation_roles=degradation_roles,
            failed_gates=failed_gates,
            pass_support=pass_support,
            gate_evaluation=gate_evaluation,
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            min_severity=min_severity,
            only_expected_severity=only_expected_severity,
            resolved_only_pass_failure=resolved_only_pass_failure,
            validation_policy=validation_policy,
        )
        == filtered_payload_impl(
            payload=payload,
            summary=summary,
            filtered_summary=filtered_summary,
            filtered_mutations=filtered_mutations,
            filtered_passes=filtered_passes,
            mismatch_counts_by_pass=mismatch_counts_by_pass,
            mismatch_observables_by_pass=mismatch_observables_by_pass,
            persisted_mismatch_priority=persisted_mismatch_priority,
            mismatch_severity_rows=mismatch_severity_rows,
            mismatch_pass_context=mismatch_pass_context,
            requested_validation_mode=requested_validation_mode,
            effective_validation_mode=effective_validation_mode,
            degraded_validation=degraded_validation,
            mismatch_degraded_passes=mismatch_degraded_passes,
            degraded_passes=degraded_passes,
            degradation_roles=degradation_roles,
            failed_gates=failed_gates,
            pass_support=pass_support,
            gate_evaluation=gate_evaluation,
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            min_severity=min_severity,
            only_expected_severity=only_expected_severity,
            resolved_only_pass_failure=resolved_only_pass_failure,
            validation_policy=validation_policy,
        )
    )


def test_report_builder_report_filters_delegate_to_shared_helpers() -> None:
    assert ReportBuilder.build_report_filters(
        "pass-a",
        "failed",
        True,
        False,
        True,
        False,
        True,
        False,
        True,
        False,
        True,
        "high",
        "medium",
        "pass-b",
    ) == report_filters_impl(
        resolved_only_pass="pass-a",
        only_status="failed",
        only_degraded=True,
        only_failed_gates=False,
        only_risky_passes=True,
        only_uncovered_passes=False,
        only_covered_passes=True,
        only_clean_passes=False,
        only_structural_risk=True,
        only_symbolic_risk=False,
        only_mismatches=True,
        min_severity="high",
        only_expected_severity="medium",
        resolved_only_pass_failure="pass-b",
    )
