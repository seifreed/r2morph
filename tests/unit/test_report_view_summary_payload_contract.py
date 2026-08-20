"""Contract tests for report summary payload helpers."""

from __future__ import annotations

from r2morph.reporting.report_context import ReportViewInputs
from r2morph.reporting.report_view_summary_payload import build_summary_payload
from tests.utils.assertions import expect


def test_build_summary_payload_summarizes_report_sections() -> None:
    payload = build_summary_payload(
        ReportViewInputs(
            pass_risk_buckets={"risky": ["alpha"], "clean": [], "covered": [], "uncovered": []},
            pass_coverage_buckets={"covered": ["alpha"], "uncovered": []},
            pass_triage_rows=[],
            normalized_pass_results=[
                {
                    "pass_name": "alpha",
                    "symbolic_requested": 2,
                    "observable_match": 1,
                    "observable_mismatch": 1,
                    "bounded_only": 0,
                    "without_coverage": 0,
                }
            ],
            pass_symbolic_summary={},
            pass_evidence_map={},
            pass_region_evidence_map={},
            pass_validation_context={},
            pass_capability_summary_map={},
            observable_mismatch_priority=[],
            observable_mismatch_map={},
            symbolic_severity_by_pass=[{"pass_name": "alpha", "severity": "low"}],
            gate_failure_priority=[{"pass_name": "alpha"}],
            gate_failure_summary={"require_pass_severity_failed": False},
            gate_failure_severity_priority=[{"severity": "low", "failure_count": 1}],
            discarded_mutation_priority=[{"pass_name": "alpha", "discarded_count": 1}],
            discarded_mutation_summary={"by_reason": {"x": 1}, "by_impact": {"high": [1]}},
            validation_adjustment_rows=[{"pass_name": "alpha", "degraded_validation": True, "gate_failure_count": 1}],
        ),
        [{"pass_name": "alpha"}],
        [{"pass_name": "alpha"}],
        {"failed_gates_rows": [{"pass_name": "alpha"}], "failed_gates_expected_severity": {"low": 1}},
        {},
    )

    expect(payload["general_summary_payload"]["pass_count"] == 1)
    expect(payload["general_gates"]["compact_summary"]["pass_count"] == 1)
    expect(payload["general_renderer_state"]["general_summary_rows"][0]["section"] == "passes")
