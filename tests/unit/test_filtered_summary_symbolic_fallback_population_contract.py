"""Contracts for symbolic fallback population helpers."""

from __future__ import annotations

from r2morph.reporting.filtered_summary_symbolic_fallback_population import (
    _apply_filtered_summary_symbolic_fallback_sections,
)


def test_apply_filtered_summary_symbolic_fallback_sections_populates_missing_rows() -> None:
    filtered_summary = {
        "symbolic_issue_passes": [],
        "symbolic_coverage_by_pass": [],
        "symbolic_severity_by_pass": [{"severity": "not-requested"}],
    }
    by_pass = {
        "fallback-pass": {
            "observable_match": 0,
            "observable_mismatch": 1,
            "bounded_only": 0,
            "without_coverage": 0,
            "symbolic_requested": 2,
        }
    }

    _apply_filtered_summary_symbolic_fallback_sections(
        filtered_summary=filtered_summary,
        by_pass=by_pass,
    )

    assert filtered_summary["symbolic_issue_passes"] == [
        {
            "pass_name": "fallback-pass",
            "severity": "mismatch",
            "observable_mismatch": 1,
            "without_coverage": 0,
            "bounded_only": 0,
        }
    ]
    assert filtered_summary["symbolic_coverage_by_pass"] == [
        {
            "pass_name": "fallback-pass",
            "symbolic_requested": 2,
            "observable_match": 0,
            "observable_mismatch": 1,
            "bounded_only": 0,
            "without_coverage": 0,
        }
    ]
    assert filtered_summary["symbolic_severity_by_pass"] == [
        {
            "pass_name": "fallback-pass",
            "severity": "mismatch",
            "issue_count": 1,
            "symbolic_requested": 2,
        }
    ]
