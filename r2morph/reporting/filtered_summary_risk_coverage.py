"""Filtered-summary risk and coverage section builders."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.filtered_summary_risk_coverage_sources import (
    _resolve_filtered_summary_risk_coverage_sources,
)


def _build_filtered_summary_risk_coverage_sections(
    *,
    summary: dict[str, Any],
    risky_pass_names: set[str],
    structural_risk_pass_names: set[str],
    symbolic_risk_pass_names: set[str],
    covered_pass_names: set[str],
    uncovered_pass_names: set[str],
    clean_pass_names: set[str],
) -> dict[str, Any]:
    """Build filtered_summary risk/coverage sections from persisted summary first."""
    buckets = _resolve_filtered_summary_risk_coverage_sources(
        summary=summary,
        risky_pass_names=risky_pass_names,
        structural_risk_pass_names=structural_risk_pass_names,
        symbolic_risk_pass_names=symbolic_risk_pass_names,
        covered_pass_names=covered_pass_names,
        uncovered_pass_names=uncovered_pass_names,
        clean_pass_names=clean_pass_names,
    )
    return {
        "pass_coverage_buckets": {
            "covered": buckets["covered"],
            "uncovered": buckets["uncovered"],
            "clean_only": buckets["clean_only"],
        },
        "pass_risk_buckets": {
            "risky": buckets["risky"],
            "structural": buckets["structural"],
            "symbolic": buckets["symbolic"],
            "clean": buckets["clean"],
            "covered": buckets["covered"],
            "uncovered": buckets["uncovered"],
        },
        "risky_passes": buckets["risky"],
        "structural_risk_passes": buckets["structural"],
        "symbolic_risk_passes": buckets["symbolic"],
        "covered_passes": buckets["covered"],
        "uncovered_passes": buckets["uncovered"],
        "clean_passes": buckets["clean"],
    }
