from __future__ import annotations

from r2morph.reporting.report_filter_messages import build_report_filter_messages


def test_report_filter_messages_cover_pass_and_risk_filters() -> None:
    messages = build_report_filter_messages(
        only_pass="pass-a",
        resolved_only_pass="pass-b",
        only_pass_failure="fail-a",
        resolved_only_pass_failure="fail-b",
        only_risky_passes=True,
        only_uncovered_passes=False,
        only_covered_passes=True,
        only_clean_passes=False,
        only_structural_risk=True,
        only_symbolic_risk=False,
        selected_risk_pass_names={"pass-a", "pass-b"},
    )

    assert messages == [
        "[bold]Pass Filter Resolution[/bold]: pass-a -> pass-b",
        "[bold]Pass Failure Filter Resolution[/bold]: fail-a -> fail-b",
        "[bold]Risky Pass Filter[/bold]: 2 risky pass(es) detected",
        "[bold]Covered Pass Filter[/bold]: 2 covered pass(es) detected",
        "[bold]Structural Risk Filter[/bold]: 2 structural-risk pass(es) detected",
    ]


def test_report_filter_messages_can_be_empty() -> None:
    assert (
        build_report_filter_messages(
            only_pass=None,
            resolved_only_pass=None,
            only_pass_failure=None,
            resolved_only_pass_failure=None,
            only_risky_passes=False,
            only_uncovered_passes=False,
            only_covered_passes=False,
            only_clean_passes=False,
            only_structural_risk=False,
            only_symbolic_risk=False,
            selected_risk_pass_names=set(),
        )
        == []
    )
