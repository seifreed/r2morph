"""Contract tests for report mismatch view helpers."""

from __future__ import annotations

from r2morph.reporting.report_view_mismatch_views import build_mismatch_views


def test_build_mismatch_views_merges_region_context() -> None:
    views = build_mismatch_views(
        observable_mismatch_priority=[{"pass_name": "alpha", "mismatch_count": 1, "observables": ["x"]}],
        normalized_pass_map={"alpha": {"role": "requested-mode", "symbolic_confidence": "high"}},
        symbolic_severity_map={"alpha": {"severity": "low", "issue_count": 2, "symbolic_requested": 3}},
        pass_validation_context={
            "alpha": {
                "degraded_execution": True,
                "degradation_triggered_by_pass": False,
            }
        },
        pass_region_evidence_map={
            "alpha": [{"mismatch_count": 2, "region_exit_equivalent": True}],
        },
    )

    assert views["mismatch_rows"][0]["region_count"] == 1
    assert views["mismatch_rows"][0]["compact_region"]["region_exit_match_count"] == 1
    assert views["mismatch_by_pass"]["alpha"]["severity"] == "low"
