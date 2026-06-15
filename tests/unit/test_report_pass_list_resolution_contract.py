from __future__ import annotations

from r2morph.reporting.report_context import PassClassFilters
from r2morph.reporting.report_pass_list_resolution import resolve_general_filtered_passes


def test_resolve_general_filtered_passes_prefers_summary_and_filters_risk_views() -> None:
    assert resolve_general_filtered_passes(
        existing_passes=[],
        summary_only_pass_view={},
        summary_general_passes=[],
        summary_general_pass_rows=[],
        summary_general_summary={"passes": ["pass-a", "pass-b"]},
        resolved_only_pass=None,
        selected_risk_pass_names={"risk-a", "risk-b"},
        pass_classes=PassClassFilters(only_risky_passes=True),
        only_failed_gates=False,
        gate_failure_priority=[],
    ) == ["risk-a", "risk-b"]


def test_resolve_general_filtered_passes_falls_back_to_requested_pass() -> None:
    assert resolve_general_filtered_passes(
        existing_passes=[],
        summary_only_pass_view={"pass-a": {}},
        summary_general_passes=[],
        summary_general_pass_rows=[],
        summary_general_summary={},
        resolved_only_pass="pass-a",
        selected_risk_pass_names=set(),
        pass_classes=PassClassFilters(),
        only_failed_gates=False,
        gate_failure_priority=[],
    ) == ["pass-a"]
