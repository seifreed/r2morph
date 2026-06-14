"""Contract tests for report pass view helpers."""

from __future__ import annotations

from r2morph.reporting.report_view_pass_views import build_pass_views


def test_build_pass_views_merges_pass_context() -> None:
    views = build_pass_views(
        normalized_pass_results=[{"pass_name": "alpha", "role": "requested-mode"}],
        pass_region_evidence_map={"alpha": [{"region": "r1"}]},
        pass_validation_context={
            "alpha": {
                "degraded_execution": True,
                "degradation_triggered_by_pass": False,
            }
        },
        pass_symbolic_summary={"alpha": {"severity": "low"}},
        pass_evidence_map={"alpha": {"evidence_count": 2}},
        pass_capability_summary_map={"alpha": {"capability_count": 1}},
        normalized_pass_map={"alpha": {"role": "requested-mode"}},
        triage_priority=[{"pass_name": "alpha"}],
        discarded_by_pass={"alpha": {"discarded_count": 1, "reasons": {"x": 1}, "impact_counts": {"high": 1}}},
        failed_gates_by_pass={"alpha": {"failure_count": 3, "strictest_expected_severity": "high"}},
    )

    assert views["general_pass_rows"][0]["gate_failure_count"] == 3
    assert views["general_pass_rows"][0]["discarded_count"] == 1
    assert views["only_pass"]["alpha"]["region_evidence"][0]["region"] == "r1"
