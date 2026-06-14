"""Contracts for filtered-summary risk/coverage source resolution."""

from __future__ import annotations

from r2morph.reporting.filtered_summary_risk_coverage_sources import (
    _resolve_filtered_summary_risk_coverage_sources,
)


def test_resolve_filtered_summary_risk_coverage_sources_prefers_persisted_summary() -> None:
    summary = {
        "report_views": {
            "general_renderer_state": {
                "general_filter_views": {
                    "risky": ["renderer-risk"],
                    "clean": ["renderer-clean"],
                }
            }
        },
        "pass_risk_buckets": {
            "risky": ["summary-risk"],
            "structural": ["summary-structural"],
            "symbolic": ["summary-symbolic"],
            "clean": ["summary-clean"],
        },
        "pass_coverage_buckets": {
            "covered": ["summary-covered"],
            "uncovered": ["summary-uncovered"],
            "clean_only": ["summary-clean-only"],
        },
    }

    resolved = _resolve_filtered_summary_risk_coverage_sources(
        summary=summary,
        risky_pass_names={"fallback-risk"},
        structural_risk_pass_names={"fallback-structural"},
        symbolic_risk_pass_names={"fallback-symbolic"},
        covered_pass_names={"fallback-covered"},
        uncovered_pass_names={"fallback-uncovered"},
        clean_pass_names={"fallback-clean"},
    )

    assert resolved == {
        "risky": ["summary-risk"],
        "structural": ["summary-structural"],
        "symbolic": ["summary-symbolic"],
        "clean": ["summary-clean"],
        "covered": ["summary-covered"],
        "uncovered": ["summary-uncovered"],
        "clean_only": ["summary-clean-only"],
    }


def test_resolve_filtered_summary_risk_coverage_sources_falls_back_to_renderer_state() -> None:
    summary = {
        "report_views": {
            "general_renderer_state": {
                "filter_views": {
                    "risky": ["renderer-risk"],
                    "structural_risk": ["renderer-structural"],
                    "symbolic_risk": ["renderer-symbolic"],
                    "clean": ["renderer-clean"],
                    "covered": ["renderer-covered"],
                    "uncovered": ["renderer-uncovered"],
                }
            }
        }
    }

    resolved = _resolve_filtered_summary_risk_coverage_sources(
        summary=summary,
        risky_pass_names={"fallback-risk"},
        structural_risk_pass_names={"fallback-structural"},
        symbolic_risk_pass_names={"fallback-symbolic"},
        covered_pass_names={"fallback-covered"},
        uncovered_pass_names={"fallback-uncovered"},
        clean_pass_names={"fallback-clean"},
    )

    assert resolved == {
        "risky": ["renderer-risk"],
        "structural": ["renderer-structural"],
        "symbolic": ["renderer-symbolic"],
        "clean": ["renderer-clean"],
        "covered": ["renderer-covered"],
        "uncovered": ["renderer-uncovered"],
        "clean_only": ["fallback-clean"],
    }
