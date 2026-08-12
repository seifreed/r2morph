"""Filtered-summary risk and coverage section builders."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.filtered_summary_risk_coverage_sources import (
    _resolve_filtered_summary_risk_coverage_sources,
)


def _build_filtered_summary_risk_coverage_sections(
    summary: dict[str, Any],
    general_state: dict[str, Any],
) -> dict[str, Any]:
    """Build filtered_summary risk/coverage sections from persisted summary first."""
    live_buckets = {
        "risky": general_state["risky_pass_names"],
        "structural": general_state["structural_risk_pass_names"],
        "symbolic": general_state["symbolic_risk_pass_names"],
        "covered": general_state["covered_pass_names"],
        "uncovered": general_state["uncovered_pass_names"],
        "clean": general_state["clean_pass_names"],
    }
    buckets = _resolve_filtered_summary_risk_coverage_sources(
        summary,
        live_buckets,
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
