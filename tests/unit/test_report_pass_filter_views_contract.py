"""Contract tests for report pass filter view normalization."""

from __future__ import annotations

from r2morph.reporting.report_pass_filter_views import _normalize_pass_filter_views
from r2morph.reporting.report_pass_filters import resolve_pass_filter_sets


def test_normalize_pass_filter_views_maps_renderer_keys() -> None:
    assert _normalize_pass_filter_views(
        {
            "general_filter_views": {
                "risky": ["pass-a"],
                "structural_risk": ["pass-b"],
                "symbolic_risk": ["pass-c"],
                "custom": ["pass-d"],
            }
        }
    ) == {
        "only_risky_passes": ["pass-a"],
        "only_structural_risk": ["pass-b"],
        "only_symbolic_risk": ["pass-c"],
        "custom": ["pass-d"],
    }


def test_resolve_pass_filter_sets_uses_normalized_renderer_views() -> None:
    summary = {
        "report_views": {
            "general_renderer_state": {
                "general_filter_views": {
                    "risky": ["pass-a"],
                    "clean": ["pass-b"],
                }
            }
        }
    }
    pass_results = {
        "pass-a": {"evidence_summary": {}, "symbolic_summary": {}},
        "pass-b": {"evidence_summary": {}, "symbolic_summary": {}},
    }

    assert resolve_pass_filter_sets(summary=summary, pass_results=pass_results) == {
        "risky": {"pass-a"},
        "structural": set(),
        "symbolic": set(),
        "clean": {"pass-b"},
        "covered": set(),
        "uncovered": {"pass-a", "pass-b"},
    }
