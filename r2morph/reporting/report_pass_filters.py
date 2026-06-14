"""Pass filter resolution helpers for reporting."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from r2morph.reporting.report_helpers import _summary_first
from r2morph.reporting.report_helpers_classification import (
    _has_structural_risk,
    _has_symbolic_risk,
    _is_clean_pass,
    _is_covered_pass,
    _is_risky_pass,
    _is_uncovered_pass,
    _pass_names_from_triage_rows,
)


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

    if not pass_filter_views and general_renderer_state.get("general_filter_views"):
        pass_filter_views = {
            (
                f"only_{key}_passes"
                if key in {"risky", "clean", "covered", "uncovered"}
                else (
                    "only_structural_risk"
                    if key == "structural_risk"
                    else "only_symbolic_risk" if key == "symbolic_risk" else key
                )
            ): value
            for key, value in dict(general_renderer_state.get("general_filter_views", {}) or {}).items()
        }

    if not pass_filter_views and general_renderer_state.get("filter_views"):
        pass_filter_views = {
            (
                f"only_{key}_passes"
                if key in {"risky", "clean", "covered", "uncovered"}
                else (
                    "only_structural_risk"
                    if key == "structural_risk"
                    else "only_symbolic_risk" if key == "symbolic_risk" else key
                )
            ): value
            for key, value in dict(general_renderer_state.get("filter_views", {}) or {}).items()
        }

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
    fallback_checks = {
        "risky": _is_risky_pass,
        "structural": _has_structural_risk,
        "symbolic": _has_symbolic_risk,
        "clean": _is_clean_pass,
        "covered": _is_covered_pass,
        "uncovered": _is_uncovered_pass,
    }

    for kind, predicate in fallback_checks.items():
        if resolved[kind]:
            continue
        matches = {
            pass_name
            for pass_name, pass_result in pass_results.items()
            if predicate(
                pass_result.get("evidence_summary"),
                pass_result.get("symbolic_summary"),
            )
        }
        if not matches and summary_pass_evidence:
            for row in summary_pass_evidence:
                pass_name_str = str(row.get("pass_name", ""))
                if pass_name_str and predicate(
                    row,
                    pass_results.get(pass_name_str, {}).get("symbolic_summary"),
                ):
                    matches.add(pass_name_str)
        resolved[kind] = matches

    return resolved
