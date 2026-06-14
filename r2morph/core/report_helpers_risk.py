"""Risk and coverage bucket helpers extracted from core.report_helpers."""

from __future__ import annotations

from typing import Any

from r2morph.core.report_helpers_coverage import (
    _summarize_pass_coverage_buckets as _summarize_pass_coverage_buckets_summary,
)


def _summarize_pass_coverage_buckets(pass_results: dict[str, Any]) -> dict[str, list[str]]:
    """Build machine-readable coverage buckets across passes."""
    return _summarize_pass_coverage_buckets_summary(pass_results)


def _summarize_pass_risk_buckets(
    pass_results: dict[str, Any],
) -> dict[str, list[str]]:
    """Build machine-readable risk buckets across passes."""
    risky: list[str] = []
    structural: list[str] = []
    symbolic: list[str] = []
    clean: list[str] = []
    for pass_name, pass_result in pass_results.items():
        evidence = pass_result.get("evidence_summary", {}) or {}
        symbolic_summary = pass_result.get("symbolic_summary", {}) or {}
        structural_issues = int(evidence.get("structural_issue_count", 0))
        symbolic_mismatch = int(evidence.get("symbolic_binary_mismatched_regions", 0))
        severity = str(symbolic_summary.get("severity", "not-requested"))
        issue_count = int(symbolic_summary.get("issue_count", 0))
        has_structural_risk = structural_issues > 0
        has_symbolic_risk = (
            symbolic_mismatch > 0
            or severity in {"mismatch", "without-coverage", "bounded-only"}
            or issue_count > 0
        )
        if has_structural_risk or has_symbolic_risk:
            risky.append(pass_name)
        if has_structural_risk:
            structural.append(pass_name)
        if has_symbolic_risk:
            symbolic.append(pass_name)
        if (
            structural_issues == 0
            and symbolic_mismatch == 0
            and severity in {"clean", "not-requested"}
            and issue_count == 0
        ):
            clean.append(pass_name)
    coverage = _summarize_pass_coverage_buckets(pass_results)
    return {
        "risky": sorted(risky),
        "structural": sorted(structural),
        "symbolic": sorted(symbolic),
        "clean": sorted(clean),
        "covered": coverage["covered"],
        "uncovered": coverage["uncovered"],
    }
