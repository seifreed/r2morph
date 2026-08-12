"""Report resolver: pure data logic for resolving report state.

Extracted from cli.py -- no logic changes.
"""

from typing import Any

from r2morph.reporting.filtered_summary_payloads import _build_general_filtered_summary
from r2morph.reporting.report_builder_models import ReportContext
from r2morph.reporting.report_context import FilterFlags, PassClassFilters
from r2morph.reporting.report_helpers_symbolic_view import _summarize_symbolic_view_from_mutations
from r2morph.reporting.report_mismatch_state import (
    resolve_only_mismatches_state as _resolve_only_mismatches_state_impl,
)
from r2morph.reporting.report_mutation_selection import _select_report_mutations
from r2morph.reporting.report_pass_resolution import resolve_only_pass_view
from r2morph.reporting.report_state import (
    resolve_general_symbolic_state as _resolve_general_symbolic_state_impl,
)
from r2morph.reporting.report_state import (
    resolve_pass_filter_sets as _resolve_pass_filter_sets_impl,
)


def _resolve_general_report_flow_state(
    payload: dict[str, Any],
    pass_results: dict[str, Any],
    context: ReportContext,
    filters: FilterFlags,
) -> dict[str, Any]:
    """Resolve summary-first state for the general report path."""
    summary = context.summary
    pass_classes = filters.pass_classes
    general_state = _resolve_general_report_state(
        summary=summary,
        payload=payload,
        pass_results=pass_results,
        pass_classes=pass_classes,
    )
    only_risky_filters = pass_classes.any_active
    mutations, adjusted_degraded_passes = _select_report_mutations(
        payload.get("mutations", []),
        context,
        filters,
        general_state["selected_risk_pass_names"],
    )
    symbolic_state = _resolve_general_symbolic_state_impl(
        summary=summary,
        mutations=mutations,
        pass_results=pass_results,
        summarize_symbolic_func=_summarize_symbolic_view_from_mutations,
    )
    filtered_summary, degradation_roles = _build_general_filtered_summary(
        context,
        filters,
        {**general_state, "mutations": mutations, "degraded_passes": adjusted_degraded_passes},
        {**symbolic_state, "pass_results": pass_results},
    )
    return {
        **general_state,
        "only_risky_filters": only_risky_filters,
        "mutations": mutations,
        "degraded_passes": adjusted_degraded_passes,
        "symbolic_state": symbolic_state,
        "filtered_summary": filtered_summary,
        "degradation_roles": degradation_roles,
    }


def _resolve_only_mismatches_state(
    *,
    summary: dict[str, Any],
    mutations: list[dict[str, Any]],
    filtered_summary: dict[str, Any],
    resolved_only_pass: str | None,
    degraded_passes: list[dict[str, Any]],
) -> dict[str, Any]:
    return _resolve_only_mismatches_state_impl(
        summary=summary,
        mutations=mutations,
        filtered_summary=filtered_summary,
        resolved_only_pass=resolved_only_pass,
        degraded_passes=degraded_passes,
    )


def _resolve_general_report_state(
    *,
    summary: dict[str, Any],
    payload: dict[str, Any],
    pass_results: dict[str, Any],
    pass_classes: PassClassFilters,
) -> dict[str, Any]:
    """Resolve summary-first pass filter state for the general report path."""
    pass_support = payload.get("pass_support", {})
    pass_filter_sets = _resolve_pass_filter_sets_impl(summary=summary, pass_results=pass_results)
    risky_pass_names = set(pass_filter_sets["risky"])
    structural_risk_pass_names = set(pass_filter_sets["structural"])
    symbolic_risk_pass_names = set(pass_filter_sets["symbolic"])
    clean_pass_names = set(pass_filter_sets["clean"])
    covered_pass_names = set(pass_filter_sets["covered"])
    uncovered_pass_names = set(pass_filter_sets["uncovered"])
    selected_risk_pass_names = set(risky_pass_names)
    if pass_classes.only_uncovered_passes:
        selected_risk_pass_names = uncovered_pass_names
    elif pass_classes.only_covered_passes:
        selected_risk_pass_names = covered_pass_names
    elif pass_classes.only_clean_passes:
        selected_risk_pass_names = clean_pass_names
    elif pass_classes.only_structural_risk and pass_classes.only_symbolic_risk:
        selected_risk_pass_names = structural_risk_pass_names & symbolic_risk_pass_names
    elif pass_classes.only_structural_risk:
        selected_risk_pass_names = structural_risk_pass_names
    elif pass_classes.only_symbolic_risk:
        selected_risk_pass_names = symbolic_risk_pass_names
    elif pass_classes.only_risky_passes:
        selected_risk_pass_names = risky_pass_names
    return {
        "pass_support": pass_support,
        "risky_pass_names": risky_pass_names,
        "structural_risk_pass_names": structural_risk_pass_names,
        "symbolic_risk_pass_names": symbolic_risk_pass_names,
        "clean_pass_names": clean_pass_names,
        "covered_pass_names": covered_pass_names,
        "uncovered_pass_names": uncovered_pass_names,
        "selected_risk_pass_names": selected_risk_pass_names,
    }


def _resolve_only_pass_view(
    *,
    summary: dict[str, Any],
    filtered_summary: dict[str, Any],
    pass_results: dict[str, Any],
    pass_name: str,
) -> tuple[
    dict[str, Any] | None,
    dict[str, Any] | None,
    dict[str, Any] | None,
    list[dict[str, Any]] | None,
]:
    """Resolve pass-scoped symbolic/evidence/context views with summary-first fallbacks."""
    return resolve_only_pass_view(
        summary=summary,
        filtered_summary=filtered_summary,
        pass_results=pass_results,
        pass_name=pass_name,
    )
