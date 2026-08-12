from __future__ import annotations

from r2morph.reporting.report_builder_models import ReportContext
from r2morph.reporting.report_context import FilterFlags
from r2morph.reporting.report_pass_list_resolution import resolve_general_filtered_passes


def _context(summary: dict[str, object], resolved_only_pass: str | None = None) -> ReportContext:
    return ReportContext(
        summary=summary,
        resolved_only_pass=resolved_only_pass,
        resolved_only_pass_failure=None,
        requested_validation_mode=None,
        effective_validation_mode=None,
        validation_policy=None,
        gate_evaluation={},
        gate_requested={},
        gate_results={},
        gate_failure_summary={},
        gate_failure_priority=[],
        gate_failure_severity_priority=[],
        failed_gates=False,
        degraded_validation=False,
        degraded_passes=[],
        degradation_roles={},
    )


def test_resolve_general_filtered_passes_prefers_summary_and_filters_risk_views() -> None:
    assert resolve_general_filtered_passes(
        {"passes": [], "general_summary": {}},
        _context({"report_views": {"general_summary": {"passes": ["pass-a", "pass-b"]}}}),
        FilterFlags(only_risky_passes=True),
        {"selected_risk_pass_names": {"risk-a", "risk-b"}},
    ) == ["risk-a", "risk-b"]


def test_resolve_general_filtered_passes_falls_back_to_requested_pass() -> None:
    assert resolve_general_filtered_passes(
        {"passes": [], "general_summary": {}},
        _context({"report_views": {"only_pass": {"pass-a": {}}}}, "pass-a"),
        FilterFlags(),
        {"selected_risk_pass_names": set()},
    ) == ["pass-a"]
