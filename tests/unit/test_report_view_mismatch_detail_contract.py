"""Contract tests for report mismatch detail helpers."""

from __future__ import annotations

from r2morph.reporting.report_view_mismatch_detail import build_mismatch_detail


def test_build_mismatch_detail_summarizes_regions() -> None:
    detail = build_mismatch_detail(
        observable_mismatch_priority=[{"pass_name": "alpha"}],
        mismatch_rows=[
            {
                "pass_name": "alpha",
                "mismatch_count": 2,
                "region_count": 1,
                "region_mismatch_count": 2,
                "region_exit_match_count": 0,
                "degraded_execution": True,
                "degradation_triggered_by_pass": True,
            }
        ],
        mismatch_by_pass={"alpha": {"mismatch_count": 2}},
    )

    assert detail["by_pass"]["alpha"]["mismatch_count"] == 2
    assert detail["compact_summary"]["degraded_pass_count"] == 1
    assert detail["summary"]["trigger_pass_count"] == 1
