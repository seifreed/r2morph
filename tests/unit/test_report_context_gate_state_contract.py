"""Contract tests for report context gate-state helpers."""

from __future__ import annotations

from r2morph.reporting.report_context_gate_state import _resolve_failed_gates_view, _resolve_report_gate_state


def test_report_context_gate_state_contract() -> None:
    summary = {
        "report_views": {
            "only_failed_gates": {
                "summary": {
                    "require_pass_severity_failures_by_pass": {"pass-a": ["expected <= medium"]},
                },
                "priority": [{"pass_name": "pass-a", "failures": ["expected <= medium"]}],
                "severity_priority": [{"severity": "medium", "failure_count": 1}],
            }
        }
    }
    payload = {
        "gate_failure_priority": [],
        "gate_failure_severity_priority": [],
    }
    gate_evaluation = {
        "require_pass_severity_failures": ["expected <= medium"],
        "require_pass_severity_failures_by_pass": {"pass-a": ["expected <= medium"]},
        "require_pass_severity_failure_count": 1,
    }

    assert _resolve_failed_gates_view(
        summary=summary,
        gate_failure_summary={"require_pass_severity_failures_by_pass": {"pass-a": ["expected <= medium"]}},
        gate_failure_priority=[],
        gate_failure_severity_priority=[],
    ) == (
        {"require_pass_severity_failures_by_pass": {"pass-a": ["expected <= medium"]}},
        [{"pass_name": "pass-a", "failures": ["expected <= medium"]}],
        [{"severity": "medium", "failure_count": 1}],
    )
    assert _resolve_report_gate_state(
        summary=summary,
        payload=payload,
        gate_evaluation=gate_evaluation,
        only_expected_severity=None,
        resolved_only_pass_failure=None,
    ) == (
        {
            "require_pass_severity_failures_by_pass": {"pass-a": ["expected <= medium"]},
            "require_pass_severity_failures": ["expected <= medium"],
            "require_pass_severity_failure_count": 1,
            "require_pass_severity_failed": True,
        },
        [{"pass_name": "pass-a", "failures": ["expected <= medium"]}],
        [{"severity": "medium", "failure_count": 1}],
        True,
    )
