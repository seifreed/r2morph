"""Contract tests for report validation detail helpers."""

from __future__ import annotations

from r2morph.reporting.report_view_validation_detail import build_validation_adjustments_detail


def test_build_validation_adjustments_detail_summarizes_rows() -> None:
    detail = build_validation_adjustments_detail(
        [
            {
                "pass_name": "alpha",
                "requested_validation_mode": "structural",
                "effective_validation_mode": "degraded",
                "triggered_adjustment": True,
                "executed_under_degraded_mode": True,
                "gate_failure_count": 2,
                "role": "degradation-trigger",
            }
        ]
    )

    assert detail["summary"]["requested_validation_mode"] == "structural"
    assert detail["summary"]["effective_validation_mode"] == "degraded"
    assert detail["compact_summary"]["row_count"] == 1
    assert detail["compact_summary"]["trigger_count"] == 1
