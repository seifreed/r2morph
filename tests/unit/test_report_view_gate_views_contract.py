"""Contract tests for report gate view helpers."""

from __future__ import annotations

from r2morph.reporting.report_view_gate_views import build_gate_views


def test_build_gate_views_summarizes_failures() -> None:
    views = build_gate_views(
        gate_failure_priority=[
            {
                "pass_name": "alpha",
                "failure_count": 2,
                "strictest_expected_severity": "high",
                "failures": [{"rule": "a"}],
            }
        ],
        gate_failure_summary={
            "require_pass_severity_failures_by_expected_severity": {"high": 1},
        },
        gate_failure_severity_priority=[{"severity": "high", "failure_count": 1}],
        normalized_pass_map={"alpha": {"role": "requested-mode"}},
    )

    assert views["failed_gates_rows"][0]["role"] == "requested-mode"
    assert views["failed_gates_compact_rows"][0]["failed"] is True
    assert views["failed_gates_expected_severity"]["high"] == 1
