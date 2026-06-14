"""Pass filter resolution helpers for reporting."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from r2morph.reporting.report_pass_filter_fallbacks import (
    _resolve_pass_filter_fallbacks as _resolve_pass_filter_fallbacks,
)
from r2morph.reporting.report_pass_filter_views import _normalize_pass_filter_views
from r2morph.reporting.report_pass_triage_rows import _pass_names_from_triage_rows
from r2morph.reporting.report_summary_lookup import _summary_first


def resolve_pass_filter_sets(
    *,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    summary_first_func: Callable[..., Any] | None = None,
) -> dict[str, set[str]]:
    """Resolve pass filter buckets from persisted summary first, then fall back."""
    report_views = dict(summary.get("report_views", {}) or {})
    general_renderer_state = dict(report_views.get("general_renderer_state", {}) or {})
    pass_filter_views = dict(report_views.get("general_filter_views", report_views.get("pass_filter_views", {})) or {})

    if not pass_filter_views:
        pass_filter_views = _normalize_pass_filter_views(general_renderer_state)

    summary_first = summary_first_func or _summary_first
    risk_buckets = dict(summary_first(summary, "pass_risk_buckets", {}) or {})
    coverage_buckets = dict(
        summary_first(
            summary,
            "pass_coverage_buckets",
            {
                "covered": (pass_filter_views or report_views.get("passes", {})).get("covered", []),
                "uncovered": (pass_filter_views or report_views.get("passes", {})).get("uncovered", []),
                "clean_only": (pass_filter_views or report_views.get("passes", {})).get("clean", []),
            },
        )
        or {}
    )

    triage_rows = list(
        summary_first(
            summary,
            "pass_triage_rows",
            report_views.get("general_triage_rows", report_views.get("triage_priority", [])),
        )
        or []
    )

    if not triage_rows and general_renderer_state.get("triage_rows"):
        triage_rows = list(general_renderer_state.get("triage_rows", []) or [])

    resolved = {
        "risky": set(pass_filter_views.get("only_risky_passes", risk_buckets.get("risky", [])) or []),
        "structural": set(
            pass_filter_views.get(
                "only_structural_risk",
                risk_buckets.get("structural", []),
            )
            or []
        ),
        "symbolic": set(pass_filter_views.get("only_symbolic_risk", risk_buckets.get("symbolic", [])) or []),
        "clean": set(pass_filter_views.get("only_clean_passes", risk_buckets.get("clean", [])) or []),
        "covered": set(
            pass_filter_views.get(
                "only_covered_passes",
                coverage_buckets.get("covered", []),
            )
            or []
        ),
        "uncovered": set(
            pass_filter_views.get(
                "only_uncovered_passes",
                coverage_buckets.get("uncovered", []),
            )
            or []
        ),
    }

    if triage_rows:
        for kind in ("risky", "structural", "symbolic", "clean", "covered", "uncovered"):
            if not resolved[kind]:
                resolved[kind] = _pass_names_from_triage_rows(triage_rows, kind=kind)

    summary_pass_evidence = list(summary_first(summary, "pass_evidence", []))
    return _resolve_pass_filter_fallbacks(
        resolved=resolved,
        summary=summary,
        pass_results=pass_results,
        summary_pass_evidence=summary_pass_evidence,
        triage_rows=triage_rows,
    )
