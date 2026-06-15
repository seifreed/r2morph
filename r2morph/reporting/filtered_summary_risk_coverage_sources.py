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
    """Resolve risk/coverage buckets, preferring the persisted summary buckets,
    then the renderer-state filter views, then the live fallback pass-name sets.

    The renderer-state tier must sit between the persisted buckets and the
    fallback sets: collapsing "persisted-or-fallback" into one lookup would
    leave the fallback sets always populated, so the renderer-state values
    could never win.
    """
    report_views = dict(summary.get("report_views", {}) or {})
    general_renderer_state = dict(report_views.get("general_renderer_state", {}) or {})
    pass_risk_buckets = dict(_summary_first(summary, "pass_risk_buckets", {}) or {})
    pass_coverage_buckets = dict(_summary_first(summary, "pass_coverage_buckets", {}) or {})
    general_filter_views = dict(report_views.get("general_filter_views", {}) or {})
    if not general_filter_views and general_renderer_state.get("general_filter_views"):
        general_filter_views = dict(general_renderer_state.get("general_filter_views", {}) or {})
    if not general_filter_views and general_renderer_state.get("filter_views"):
        general_filter_views = dict(general_renderer_state.get("filter_views", {}) or {})

    def _bucket(
        persisted: dict[str, Any],
        persisted_key: str,
        renderer_key: str | None,
        fallback: set[str],
    ) -> list[str]:
        persisted_values = persisted.get(persisted_key)
        if persisted_values:
            return sorted(str(name) for name in persisted_values if name)
        if renderer_key is not None:
            renderer_values = general_filter_views.get(renderer_key)
            if renderer_values:
                return sorted(str(name) for name in renderer_values if name)
        return sorted(fallback)

    return {
        "risky": _bucket(pass_risk_buckets, "risky", "risky", risky_pass_names),
        "structural": _bucket(pass_risk_buckets, "structural", "structural_risk", structural_risk_pass_names),
        "symbolic": _bucket(pass_risk_buckets, "symbolic", "symbolic_risk", symbolic_risk_pass_names),
        "clean": _bucket(pass_risk_buckets, "clean", "clean", clean_pass_names),
        "covered": _bucket(pass_coverage_buckets, "covered", "covered", covered_pass_names),
        "uncovered": _bucket(pass_coverage_buckets, "uncovered", "uncovered", uncovered_pass_names),
        "clean_only": _bucket(pass_coverage_buckets, "clean_only", None, clean_pass_names),
    }
