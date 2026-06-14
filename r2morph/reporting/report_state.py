"""Report state resolution functions extracted from cli.py."""

from typing import Any

from r2morph.reporting.report_helpers import _normalized_pass_map, _summary_first
from r2morph.reporting.report_pass_filters import (
    resolve_pass_filter_sets as _resolve_pass_filter_sets_impl,
)


def resolve_general_symbolic_state(
    *,
    summary: dict[str, Any],
    mutations: list[dict[str, Any]],
    pass_results: dict[str, Any],
    summarize_symbolic_func: Any,
    render_symbolic_func: Any,
) -> dict[str, Any]:
    """
    Resolve symbolic summary inputs for the general report path.

    Args:
        summary: Report summary dict
        mutations: List of mutations
        pass_results: Pass results dict
        summarize_symbolic_func: Function to summarize symbolic view
        render_symbolic_func: Function to render symbolic sections

    Returns:
        Dict with symbolic state
    """
    (
        symbolic_requested,
        observable_match,
        observable_mismatch,
        bounded_only,
        observable_not_run,
        by_pass,
        mismatch_rows,
    ) = summarize_symbolic_func(summary=summary, mutations=mutations)

    render_symbolic_func(
        symbolic_requested=symbolic_requested,
        observable_match=observable_match,
        observable_mismatch=observable_mismatch,
        bounded_only=bounded_only,
        observable_not_run=observable_not_run,
        summary=summary,
        pass_results=pass_results,
        by_pass=by_pass,
        mismatch_rows=mismatch_rows,
    )

    summary_normalized_pass_results = list(summary.get("normalized_pass_results", []) or [])
    return {
        "symbolic_requested": symbolic_requested,
        "observable_match": observable_match,
        "observable_mismatch": observable_mismatch,
        "bounded_only": bounded_only,
        "observable_not_run": observable_not_run,
        "by_pass": by_pass,
        "summary_normalized_pass_results": summary_normalized_pass_results,
        "normalized_pass_map": _normalized_pass_map(summary_normalized_pass_results),
    }


def resolve_mismatch_view(
    *,
    summary: dict[str, Any],
    mutations: list[dict[str, Any]],
) -> tuple[dict[str, int], dict[str, list[str]], list[dict[str, Any]]]:
    """
    Resolve mismatch counts/observables/priority from persisted summary first.

    Args:
        summary: Report summary dict
        mutations: List of mutations

    Returns:
        Tuple of (counts_by_pass, observables_by_pass, mismatch_priority)
    """
    report_views = dict(summary.get("report_views", {}) or {})
    only_mismatches_view = dict(report_views.get("only_mismatches", {}) or {})
    mismatch_map = dict(
        _summary_first(
            summary,
            "observable_mismatch_map",
            only_mismatches_view.get("by_pass", report_views.get("mismatch_map", {})),
        )
        or {}
    )
    mismatch_priority = list(
        _summary_first(
            summary,
            "observable_mismatch_priority",
            only_mismatches_view.get("priority", report_views.get("mismatch_priority", [])),
        )
        or []
    )
    mismatch_view = list(only_mismatches_view.get("rows", report_views.get("mismatch_view", [])) or [])
    mismatch_compact_rows = list(only_mismatches_view.get("compact_rows", []) or [])

    if mismatch_map:
        counts_by_pass = {pass_name: int(row.get("mismatch_count", 0)) for pass_name, row in mismatch_map.items()}
        observables_by_pass = {pass_name: list(row.get("observables", [])) for pass_name, row in mismatch_map.items()}
    else:
        persisted_rows = list(_summary_first(summary, "observable_mismatch_by_pass", []))
        counts_by_pass = {
            row.get("pass_name", "unknown"): int(row.get("mismatch_count", 0))
            for row in persisted_rows
            if row.get("pass_name")
        }
        observables_by_pass = {
            row.get("pass_name", "unknown"): list(row.get("observables", []))
            for row in persisted_rows
            if row.get("pass_name")
        }
        if not counts_by_pass and mismatch_compact_rows:
            counts_by_pass = {
                str(row.get("pass_name")): int(row.get("mismatch_count", 0))
                for row in mismatch_compact_rows
                if row.get("pass_name")
            }
        if not observables_by_pass and mismatch_view:
            observables_by_pass = {
                str(row.get("pass_name")): list(row.get("observables", []))
                for row in mismatch_view
                if row.get("pass_name")
            }

    for mutation in mutations:
        pass_name = mutation.get("pass_name", "unknown")
        counts_by_pass[pass_name] = counts_by_pass.get(pass_name, 0) + 1
        mismatch_observables = mutation.get("metadata", {}).get("symbolic_observable_mismatches", [])
        if mismatch_observables:
            merged = set(observables_by_pass.get(pass_name, []))
            merged.update(mismatch_observables)
            observables_by_pass[pass_name] = sorted(merged)

    return counts_by_pass, observables_by_pass, mismatch_priority or mismatch_view

def resolve_pass_filter_sets(
    *,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
) -> dict[str, set[str]]:
    return _resolve_pass_filter_sets_impl(summary=summary, pass_results=pass_results)
