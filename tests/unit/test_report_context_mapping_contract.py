"""Contract tests for the report views compatibility adapter."""

from __future__ import annotations

from r2morph.reporting.report_context import ReportViews


def test_report_views_mapping_contract() -> None:
    views = ReportViews(
        general_summary={"total_tests": 2},
        passes={"p1": ["clean"]},
        only_failed_gates={"summary": {"failed": False}},
    )

    assert views["general_summary"] == {"total_tests": 2}
    assert "passes" in views
    assert views.get("missing", {"default": True}) == {"default": True}
    assert views.keys() == [
        "general_passes",
        "general_pass_rows",
        "general_summary",
        "general_summary_rows",
        "general_renderer_state",
        "general_triage_rows",
        "general_filter_views",
        "general_symbolic",
        "general_gates",
        "general_degradation",
        "general_discards",
        "passes",
        "triage_priority",
        "only_pass",
        "pass_filter_views",
        "mismatch_priority",
        "mismatch_map",
        "mismatch_view",
        "only_mismatches",
        "failed_gates",
        "only_failed_gates",
        "validation_adjustments",
        "discarded_view",
    ]
    assert dict(views)["passes"] == {"p1": ["clean"]}
    assert views.to_dict()["only_failed_gates"] == {"summary": {"failed": False}}
