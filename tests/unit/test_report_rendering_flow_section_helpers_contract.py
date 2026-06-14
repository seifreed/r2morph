from r2morph.reporting.report_rendering_flow_section_helpers import (
    build_degradation_summary_lines,
    build_gate_summary_lines,
)


def test_build_degradation_summary_lines_includes_roles_and_severity_rows() -> None:
    lines = build_degradation_summary_lines(
        requested_validation_mode="symbolic",
        effective_validation_mode="runtime",
        degraded_validation=True,
        validation_policy={"policy": "fallback", "reason": "timeout"},
        degraded_passes=[{"pass_name": "alpha", "confidence": "high"}],
        degradation_roles={"trigger": 2},
        symbolic_severity_rows=[
            {
                "pass_name": "alpha",
                "severity": "mismatch",
                "issue_count": 3,
                "symbolic_requested": 1,
            }
        ],
    )

    assert lines == [
        "[bold]Validation Mode Adjustment[/bold]: requested=symbolic, effective=runtime",
        "  policy=fallback, reason=timeout",
        "[bold]Degraded Passes[/bold]:",
        "  [yellow]alpha[/yellow]: symbolic confidence=high",
        "[bold]Degradation Roles[/bold]:",
        "  trigger: 2",
        "[bold]Degraded Severity Priority[/bold]:",
        "  [cyan]alpha[/cyan]: severity=mismatch, issue_count=3, symbolic_requested=1",
    ]


def test_build_gate_summary_lines_includes_failures_and_counts() -> None:
    lines = build_gate_summary_lines(
        gate_evaluation={"min_severity": True},
        gate_requested={
            "min_severity": "high",
            "require_pass_severity": [
                {"pass_name": "alpha", "max_severity": "medium"},
            ],
        },
        gate_results={
            "all_passed": False,
            "min_severity_passed": True,
            "require_pass_severity_passed": False,
            "require_pass_severity_failures": ["alpha<=medium"],
        },
        gate_failure_summary={
            "min_severity_failed": True,
            "require_pass_severity_failure_count": 1,
            "require_pass_severity_failures_by_expected_severity": {"medium": 1},
            "require_pass_severity_failures_by_pass": {
                "alpha": ["alpha<=medium"],
            },
        },
        gate_failure_priority=[
            {
                "pass_name": "alpha",
                "failure_count": 1,
                "strictest_expected_severity": "medium",
                "failures": ["alpha<=medium"],
            }
        ],
        gate_failure_severity_priority=[
            {"severity": "medium", "failure_count": 1},
        ],
    )

    assert lines == [
        "[bold]Gate Evaluation[/bold]: all_passed=no",
        "  min_severity=high, passed=yes",
        "  require_pass_severity=alpha<=medium, passed=no",
        "  failures: alpha<=medium",
        "[bold]Gate Failure Summary[/bold]: min_severity_failed=yes, require_pass_failures=1",
        "  expected_severity_counts=medium:1",
        "  expected_severity_priority=medium:1",
        "[bold]Gate Failure By Pass[/bold]:",
        "  [yellow]alpha[/yellow] (count=1, strictest_expected=medium): alpha<=medium",
    ]
