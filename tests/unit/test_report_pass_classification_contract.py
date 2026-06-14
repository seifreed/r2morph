"""Contracts for pass-classification reporting helpers."""

from __future__ import annotations

from r2morph.reporting.report_pass_classification import (
    _has_structural_risk,
    _has_symbolic_risk,
    _is_clean_pass,
    _is_covered_pass,
    _is_risky_pass,
    _is_uncovered_pass,
)


def test_pass_classification_predicates_cover_risk_and_clean_variants() -> None:
    risky_evidence = {"structural_issue_count": 1}
    risky_symbolic = {"severity": "mismatch", "issue_count": 1}
    clean_evidence = {"structural_issue_count": 0, "symbolic_binary_mismatched_regions": 0}
    clean_symbolic = {"severity": "clean", "issue_count": 0, "symbolic_requested": 1, "without_coverage": 0}
    covered_evidence = {"structural_issue_count": 0, "symbolic_binary_regions_checked": 1}
    uncovered_symbolic = {"severity": "clean", "issue_count": 0, "symbolic_requested": 1, "without_coverage": 1}

    assert _is_risky_pass(risky_evidence, None)
    assert _is_risky_pass(None, risky_symbolic)
    assert _has_structural_risk(risky_evidence, None)
    assert _has_symbolic_risk(None, risky_symbolic)
    assert _is_clean_pass(clean_evidence, clean_symbolic)
    assert _is_covered_pass(covered_evidence, clean_symbolic)
    assert _is_uncovered_pass(clean_evidence, uncovered_symbolic)
