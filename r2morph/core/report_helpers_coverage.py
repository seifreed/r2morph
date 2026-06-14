"""Coverage bucket helpers for report generation."""

from __future__ import annotations

from typing import Any


def _summarize_pass_coverage_buckets(pass_results: dict[str, Any]) -> dict[str, list[str]]:
    """Build machine-readable coverage buckets across passes."""
    covered: list[str] = []
    uncovered: list[str] = []
    clean_only: list[str] = []
    for pass_name, pass_result in pass_results.items():
        evidence = pass_result.get("evidence_summary", {}) or {}
        symbolic = pass_result.get("symbolic_summary", {}) or {}
        structural_issues = int(evidence.get("structural_issue_count", 0))
        symbolic_mismatch = int(evidence.get("symbolic_binary_mismatched_regions", 0))
        severity = str(symbolic.get("severity", "not-requested"))
        issue_count = int(symbolic.get("issue_count", 0))
        clean = (
            structural_issues == 0
            and symbolic_mismatch == 0
            and severity in {"clean", "not-requested"}
            and issue_count == 0
        )
        if not clean:
            continue
        clean_only.append(pass_name)
        symbolic_requested = int(symbolic.get("symbolic_requested", 0))
        without_coverage = int(symbolic.get("without_coverage", 0))
        checked_regions = int(evidence.get("symbolic_binary_regions_checked", 0))
        if symbolic_requested > 0 and without_coverage == 0 and checked_regions > 0:
            covered.append(pass_name)
        else:
            uncovered.append(pass_name)
    return {
        "covered": sorted(covered),
        "uncovered": sorted(uncovered),
        "clean_only": sorted(clean_only),
    }
