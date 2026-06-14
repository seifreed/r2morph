"""Contracts for filtered-summary symbolic fallback builders."""

from __future__ import annotations

from r2morph.reporting.filtered_summary_symbolic_fallbacks import (
    _build_filtered_summary_symbolic_fallback_sections,
)


def test_build_filtered_summary_symbolic_fallback_sections_derives_rows_from_by_pass() -> None:
    by_pass = {
        "mismatch-pass": {
            "observable_match": 0,
            "observable_mismatch": 2,
            "bounded_only": 0,
            "without_coverage": 0,
            "symbolic_requested": 3,
        },
        "coverage-pass": {
            "observable_match": 1,
            "observable_mismatch": 0,
            "bounded_only": 0,
            "without_coverage": 0,
            "symbolic_requested": 2,
        },
        "quiet-pass": {
            "observable_match": 0,
            "observable_mismatch": 0,
            "bounded_only": 0,
            "without_coverage": 0,
            "symbolic_requested": 0,
        },
    }

    fallback_sections = _build_filtered_summary_symbolic_fallback_sections(by_pass=by_pass)

    assert fallback_sections["symbolic_issue_passes"] == [
        {
            "pass_name": "mismatch-pass",
            "severity": "mismatch",
            "observable_mismatch": 2,
            "without_coverage": 0,
            "bounded_only": 0,
        }
    ]
    assert fallback_sections["symbolic_coverage_by_pass"] == [
        {
            "pass_name": "coverage-pass",
            "symbolic_requested": 2,
            "observable_match": 1,
            "observable_mismatch": 0,
            "bounded_only": 0,
            "without_coverage": 0,
        },
        {
            "pass_name": "mismatch-pass",
            "symbolic_requested": 3,
            "observable_match": 0,
            "observable_mismatch": 2,
            "bounded_only": 0,
            "without_coverage": 0,
        },
    ]
    assert fallback_sections["symbolic_severity_by_pass"] == [
        {
            "pass_name": "coverage-pass",
            "severity": "bounded-only",
            "issue_count": 0,
            "symbolic_requested": 2,
        },
        {
            "pass_name": "mismatch-pass",
            "severity": "mismatch",
            "issue_count": 2,
            "symbolic_requested": 3,
        },
    ]


def test_build_filtered_summary_symbolic_fallback_sections_handles_empty_input() -> None:
    assert _build_filtered_summary_symbolic_fallback_sections(by_pass={}) == {
        "symbolic_issue_passes": [],
        "symbolic_coverage_by_pass": [],
        "symbolic_severity_by_pass": [],
    }
