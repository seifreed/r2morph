"""Contract tests for report pass view helpers."""

from __future__ import annotations

from r2morph.reporting.report_context import ReportViewInputs
from r2morph.reporting.report_view_pass_views import build_pass_views
from tests.utils.assertions import expect
from tests.utils.field_names import ONLY_MUTATION_KEY

_EXPECTED_VIEWS_GENERAL_PASS_ROWS_0_GATE_FAILURE_COUNT_3 = 3


def test_build_pass_views_merges_pass_context() -> None:
    views = build_pass_views(
        ReportViewInputs(
            pass_risk_buckets={},
            pass_coverage_buckets={},
            pass_triage_rows=[],
            normalized_pass_results=[{"pass_name": "alpha", "role": "requested-mode"}],
            pass_symbolic_summary={"alpha": {"severity": "low"}},
            pass_evidence_map={"alpha": {"evidence_count": 2}},
            pass_region_evidence_map={"alpha": [{"region": "r1"}]},
            pass_validation_context={
                "alpha": {
                    "degraded_execution": True,
                    "degradation_triggered_by_pass": False,
                }
            },
            pass_capability_summary_map={"alpha": {"capability_count": 1}},
            observable_mismatch_priority=[],
            observable_mismatch_map={},
            symbolic_severity_by_pass=[],
            gate_failure_priority=[],
            gate_failure_summary={},
            gate_failure_severity_priority=[],
            discarded_mutation_priority=[],
            discarded_mutation_summary={},
            validation_adjustment_rows=[],
        ),
        {
            "normalized_pass_map": {"alpha": {"role": "requested-mode"}},
            "triage_priority": [{"pass_name": "alpha"}],
            "discarded_by_pass": {"alpha": {"discarded_count": 1, "reasons": {"x": 1}, "impact_counts": {"high": 1}}},
        },
        {"failed_gates_by_pass": {"alpha": {"failure_count": 3, "strictest_expected_severity": "high"}}},
    )

    expect(
        views["general_pass_rows"][0]["gate_failure_count"] == _EXPECTED_VIEWS_GENERAL_PASS_ROWS_0_GATE_FAILURE_COUNT_3
    )
    expect(views["general_pass_rows"][0]["discarded_count"] == 1)
    expect(views[ONLY_MUTATION_KEY]["alpha"]["region_evidence"][0]["region"] == "r1")
