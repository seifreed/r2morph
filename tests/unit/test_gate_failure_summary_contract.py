from r2morph.reporting.gate_failure_summary import (
    build_gate_failure_priority,
    build_gate_failure_severity_priority,
    summarize_gate_failures,
)
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY

_EXPECTED_SUMMARY_REQUIRE_PASS_SEVERITY_FAILURE_COUNT_2 = 2


def test_gate_failure_summary_contract() -> None:
    gate_evaluation = {
        "requested": {"min_severity": "mismatch"},
        "results": {
            "min_severity_passed": False,
            "all_passed": False,
            "require_pass_severity_failures": [
                "mutate=mismatch(expected <= clean)",
                "fuzz=without-coverage(expected <= bounded-only)",
            ],
        },
    }

    summary = summarize_gate_failures(gate_evaluation)
    expect(not (summary["min_severity_failed"] is not True))
    expect(summary["require_pass_severity_failure_count"] == _EXPECTED_SUMMARY_REQUIRE_PASS_SEVERITY_FAILURE_COUNT_2)

    priority = build_gate_failure_priority(summary)
    expect(priority[0][MUTATION_NAME_KEY] == "fuzz")
    expect(priority[0]["strictest_expected_severity"] == "bounded-only")

    severity_priority = build_gate_failure_severity_priority(summary)
    expect(severity_priority[0]["severity"] == "bounded-only")
