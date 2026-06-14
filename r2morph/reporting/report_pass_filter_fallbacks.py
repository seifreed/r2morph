"""Fallback evaluation helpers for report pass filters."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from r2morph.reporting.report_helpers_classification import (
    _has_structural_risk,
    _has_symbolic_risk,
    _is_clean_pass,
    _is_covered_pass,
    _is_risky_pass,
    _is_uncovered_pass,
)
from r2morph.reporting.report_pass_triage_rows import _pass_names_from_triage_rows

PassFilterBuckets = dict[str, set[str]]


def _resolve_pass_filter_fallbacks(
    *,
    resolved: PassFilterBuckets,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    summary_pass_evidence: list[dict[str, Any]],
    triage_rows: list[dict[str, Any]],
) -> PassFilterBuckets:
    """Fill empty pass-filter buckets using triage rows and pass evidence."""
    fallback_checks: dict[str, Callable[[dict[str, Any] | None, dict[str, Any] | None], bool]] = {
        "risky": _is_risky_pass,
        "structural": _has_structural_risk,
        "symbolic": _has_symbolic_risk,
        "clean": _is_clean_pass,
        "covered": _is_covered_pass,
        "uncovered": _is_uncovered_pass,
    }

    if triage_rows:
        for kind in ("risky", "structural", "symbolic", "clean", "covered", "uncovered"):
            if not resolved[kind]:
                resolved[kind] = _pass_names_from_triage_rows(triage_rows, kind=kind)

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
                if pass_name_str and predicate(row, pass_results.get(pass_name_str, {}).get("symbolic_summary")):
                    matches.add(pass_name_str)
        resolved[kind] = matches

    return resolved
