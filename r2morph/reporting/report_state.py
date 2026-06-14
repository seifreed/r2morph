"""Report state resolution functions extracted from cli.py."""

from typing import Any

from r2morph.reporting.report_helpers import _normalized_pass_map
from r2morph.reporting.report_mismatch_resolution import (
    _merge_mismatch_observables_from_mutations as _merge_mismatch_observables_from_mutations,
)
from r2morph.reporting.report_mismatch_resolution import (
    _resolve_mismatch_view_from_summary as _resolve_mismatch_view_from_summary,
)
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
    counts_by_pass, observables_by_pass, mismatch_priority, mismatch_view = _resolve_mismatch_view_from_summary(summary)
    counts_by_pass, observables_by_pass = _merge_mismatch_observables_from_mutations(
        counts_by_pass,
        observables_by_pass,
        mutations,
    )
    return counts_by_pass, observables_by_pass, mismatch_priority or mismatch_view


def resolve_pass_filter_sets(
    *,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
) -> dict[str, set[str]]:
    return _resolve_pass_filter_sets_impl(summary=summary, pass_results=pass_results)
