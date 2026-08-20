from __future__ import annotations

from r2morph.reporting.report_gate_filters import _filter_failed_gates_view
from r2morph.reporting.report_severity_parsing import _expected_severity_rank_from_failure
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY, RESOLVED_FAILED_MUTATION_KEY


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
        **{RESOLVED_FAILED_MUTATION_KEY: "PassA"},
    )

    expect(summary["require_pass_severity_failure_count"] == 1)
    expect(priority[0][MUTATION_NAME_KEY] == "PassA")
    expect(severity_priority[0]["severity"] == "mismatch")
    expect(not (failed is not True))


def test_expected_severity_rank_from_failure_parses_failure_text() -> None:
    expect(_expected_severity_rank_from_failure("PassA=clean(expected <= mismatch)") == 0)
