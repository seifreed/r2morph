from __future__ import annotations

from r2morph.reporting.report_gate_filters import (
    _expected_severity_rank_from_failure,
    _filter_failed_gates_view,
)
from r2morph.reporting.report_severity_parsing import (
    _expected_severity_rank_from_failure as canonical_expected_severity_rank_from_failure,
)


def test_filter_failed_gates_view_applies_expected_severity_and_pass_filters() -> None:
    summary, priority, severity_priority, failed = _filter_failed_gates_view(
        gate_failure_summary={
            "require_pass_severity_failures_by_pass": {"PassA": ["PassA=clean(expected <= mismatch)"]},
            "require_pass_severity_failures_by_expected_severity": {"mismatch": 1},
            "require_pass_severity_failures": ["PassA=clean(expected <= mismatch)"],
            "require_pass_severity_failure_count": 1,
            "require_pass_severity_failed": True,
        },
        gate_failure_priority=[
            {
                "pass_name": "PassA",
                "failure_count": 1,
                "strictest_expected_severity": "mismatch",
                "failures": ["PassA=clean(expected <= mismatch)"],
            }
        ],
        gate_failure_severity_priority=[
            {"severity": "mismatch", "failure_count": 1},
        ],
        only_expected_severity="mismatch",
        resolved_only_pass_failure="PassA",
    )

    assert summary["require_pass_severity_failure_count"] == 1
    assert priority[0]["pass_name"] == "PassA"
    assert severity_priority[0]["severity"] == "mismatch"
    assert failed is True


def test_expected_severity_rank_from_failure_parses_failure_text() -> None:
    assert _expected_severity_rank_from_failure("PassA=clean(expected <= mismatch)") == 0
    assert _expected_severity_rank_from_failure is canonical_expected_severity_rank_from_failure
