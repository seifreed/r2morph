from r2morph.reporting.gate_failure_summary import (
    build_gate_failure_priority,
    build_gate_failure_severity_priority,
    summarize_gate_failures,
)


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
    assert summary["min_severity_failed"] is True
    assert summary["require_pass_severity_failure_count"] == 2

    priority = build_gate_failure_priority(summary)
    assert priority[0]["pass_name"] == "fuzz"

    severity_priority = build_gate_failure_severity_priority(summary)
    assert severity_priority[0]["severity"] == "bounded-only"
