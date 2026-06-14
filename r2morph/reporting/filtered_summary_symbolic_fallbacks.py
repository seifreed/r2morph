"""Fallback symbolic-section builders for filtered summaries."""

from __future__ import annotations

from typing import Any


def _build_filtered_summary_symbolic_fallback_sections(
    *,
    by_pass: dict[str, dict[str, int]],
) -> dict[str, list[dict[str, Any]]]:
    """Build symbolic fallback rows from per-pass counters."""
    if not by_pass:
        return {
            "symbolic_issue_passes": [],
            "symbolic_coverage_by_pass": [],
            "symbolic_severity_by_pass": [],
        }

    symbolic_issue_passes = [
        {
            "pass_name": pass_name,
            "severity": (
                "mismatch"
                if pass_stats["observable_mismatch"] > 0
                else "without-coverage" if pass_stats["without_coverage"] > 0 else "bounded-only"
            ),
            "observable_mismatch": pass_stats["observable_mismatch"],
            "without_coverage": pass_stats["without_coverage"],
            "bounded_only": pass_stats["bounded_only"],
        }
        for pass_name, pass_stats in sorted(by_pass.items())
        if pass_stats["observable_mismatch"] > 0 or pass_stats["without_coverage"] > 0 or pass_stats["bounded_only"] > 0
    ]
    symbolic_coverage_by_pass = [
        {
            "pass_name": pass_name,
            "symbolic_requested": pass_stats["symbolic_requested"],
            "observable_match": pass_stats["observable_match"],
            "observable_mismatch": pass_stats["observable_mismatch"],
            "bounded_only": pass_stats["bounded_only"],
            "without_coverage": pass_stats["without_coverage"],
        }
        for pass_name, pass_stats in sorted(by_pass.items())
        if pass_stats["symbolic_requested"] > 0
    ]
    symbolic_severity_by_pass = [
        {
            "pass_name": pass_name,
            "severity": (
                "mismatch"
                if pass_stats["observable_mismatch"] > 0
                else "without-coverage" if pass_stats["without_coverage"] > 0 else "bounded-only"
            ),
            "issue_count": pass_stats["observable_mismatch"]
            + pass_stats["without_coverage"]
            + pass_stats["bounded_only"],
            "symbolic_requested": pass_stats["symbolic_requested"],
        }
        for pass_name, pass_stats in sorted(by_pass.items())
        if pass_stats["symbolic_requested"] > 0
    ]
    return {
        "symbolic_issue_passes": symbolic_issue_passes,
        "symbolic_coverage_by_pass": symbolic_coverage_by_pass,
        "symbolic_severity_by_pass": symbolic_severity_by_pass,
    }
