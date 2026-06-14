"""Source-resolution helpers for filtered-summary risk/coverage sections."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_summary_lookup import _summary_first


def _resolve_filtered_summary_risk_coverage_sources(
    *,
    summary: dict[str, Any],
    risky_pass_names: set[str],
    structural_risk_pass_names: set[str],
    symbolic_risk_pass_names: set[str],
    covered_pass_names: set[str],
    uncovered_pass_names: set[str],
    clean_pass_names: set[str],
) -> dict[str, list[str]]:
    """Resolve risk/coverage buckets from persisted summary first, then fall back."""
    report_views = dict(summary.get("report_views", {}) or {})
    general_renderer_state = dict(report_views.get("general_renderer_state", {}) or {})
    pass_risk_buckets = dict(_summary_first(summary, "pass_risk_buckets", {}) or {})
    pass_coverage_buckets = dict(_summary_first(summary, "pass_coverage_buckets", {}) or {})
    general_filter_views = dict(report_views.get("general_filter_views", {}) or {})
    if not general_filter_views and general_renderer_state.get("general_filter_views"):
        general_filter_views = dict(general_renderer_state.get("general_filter_views", {}) or {})
    if not general_filter_views and general_renderer_state.get("filter_views"):
        general_filter_views = dict(general_renderer_state.get("filter_views", {}) or {})

    risky = sorted(pass_risk_buckets.get("risky", list(risky_pass_names)) or list(risky_pass_names))
    if not risky and general_filter_views.get("risky"):
        risky = sorted(str(name) for name in general_filter_views.get("risky", []) if name)
    structural = sorted(
        pass_risk_buckets.get("structural", list(structural_risk_pass_names)) or list(structural_risk_pass_names)
    )
    if not structural and general_filter_views.get("structural_risk"):
        structural = sorted(str(name) for name in general_filter_views.get("structural_risk", []) if name)
    symbolic = sorted(
        pass_risk_buckets.get("symbolic", list(symbolic_risk_pass_names)) or list(symbolic_risk_pass_names)
    )
    if not symbolic and general_filter_views.get("symbolic_risk"):
        symbolic = sorted(str(name) for name in general_filter_views.get("symbolic_risk", []) if name)
    clean = sorted(pass_risk_buckets.get("clean", list(clean_pass_names)) or list(clean_pass_names))
    if not clean and general_filter_views.get("clean"):
        clean = sorted(str(name) for name in general_filter_views.get("clean", []) if name)
    covered = sorted(pass_coverage_buckets.get("covered", list(covered_pass_names)) or list(covered_pass_names))
    if not covered and general_filter_views.get("covered"):
        covered = sorted(str(name) for name in general_filter_views.get("covered", []) if name)
    uncovered = sorted(pass_coverage_buckets.get("uncovered", list(uncovered_pass_names)) or list(uncovered_pass_names))
    if not uncovered and general_filter_views.get("uncovered"):
        uncovered = sorted(str(name) for name in general_filter_views.get("uncovered", []) if name)
    clean_only = sorted(pass_coverage_buckets.get("clean_only", list(clean_pass_names)) or list(clean_pass_names))
    return {
        "risky": risky,
        "structural": structural,
        "symbolic": symbolic,
        "clean": clean,
        "covered": covered,
        "uncovered": uncovered,
        "clean_only": clean_only,
    }
