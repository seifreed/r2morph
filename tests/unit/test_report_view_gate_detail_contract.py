"""Contract tests for report gate detail helpers."""

from __future__ import annotations

from r2morph.reporting.report_view_gate_detail import build_gate_detail


def test_build_gate_detail_summarizes_failures() -> None:
    detail = build_gate_detail(
        gate_failure_priority=[{"pass_name": "alpha"}],
        gate_failure_summary={
            "require_pass_severity_failed": True,
            "require_pass_severity_failure_count": 1,
        },
        gate_failure_severity_priority=[{"severity": "medium", "failure_count": 1}],
        failed_gates_rows=[{"pass_name": "alpha", "failure_count": 1, "role": "failed"}],
        failed_gates_by_pass={"alpha": {"failure_count": 1}},
        failed_gates_expected_severity={"medium": 1},
    )

    assert detail["failed"] is True
    assert detail["failure_count"] == 1
    assert detail["compact_summary"]["pass_count"] == 1
    assert detail["passes"] == ["alpha"]
