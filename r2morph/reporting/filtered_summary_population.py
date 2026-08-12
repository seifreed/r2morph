"""Filtered-summary population helpers.

These helpers populate the mutable filtered_summary structure after the
section payloads are resolved.
"""

from typing import Any

from r2morph.reporting.filtered_summary_pass_details import (
    PassDetailPopulation,
    _populate_pass_capabilities_and_context,
    _populate_pass_evidence,
)
from r2morph.reporting.filtered_summary_risk import _apply_risk_filters
from r2morph.reporting.filtered_summary_symbolic import (
    SymbolicPopulation,
    _populate_filtered_summary_symbolic_sections,
    _populate_symbolic_coverage_and_severity,
    _populate_symbolic_issue_passes,
)
from r2morph.reporting.filtered_summary_symbolic_fallback_population import (
    _apply_filtered_summary_symbolic_fallback_sections,
)
from r2morph.reporting.filtered_summary_triage import _populate_triage_and_results
from r2morph.reporting.report_builder_models import ReportContext
from r2morph.reporting.report_context import FilterFlags
from r2morph.reporting.report_helpers import _symbolic_summary_from_normalized_row
from r2morph.reporting.report_view_resolution import _resolve_summary_pass_sources


def _fill_pass_map_from_summary(filtered_summary: dict[str, Any], key: str, source_map: dict[str, Any]) -> None:
    """Fill an empty filtered_summary pass-map from a summary source, keeping visible passes."""
    if filtered_summary[key] or not source_map:
        return
    visible_passes = set(filtered_summary["passes"])
    filtered_summary[key] = {
        pass_name: dict(value)
        for pass_name, value in source_map.items()
        if not visible_passes or pass_name in visible_passes
    }


def _populate_filtered_summary_pass_sections(
    filtered_summary: dict[str, Any],
    context: ReportContext,
    filters: FilterFlags,
    general_state: dict[str, Any],
    symbolic_state: dict[str, Any],
) -> dict[str, int]:
    """Populate filtered_summary pass-related sections using summary-first data."""
    summary = context.summary
    pass_results = symbolic_state["pass_results"]
    degraded_passes = general_state["degraded_passes"]
    by_pass = symbolic_state["by_pass"]
    normalized_pass_map = symbolic_state["normalized_pass_map"]
    selected_risk_pass_names = general_state["selected_risk_pass_names"]
    only_risky_filters = filters.pass_classes.any_active
    summary_sources = _resolve_summary_pass_sources(summary)
    summary_pass_validation_context = summary_sources["pass_validation_context"]
    summary_pass_symbolic_summary = summary_sources["pass_symbolic_summary"]
    summary_pass_capabilities = summary_sources["pass_capabilities"]

    detail_population = PassDetailPopulation(
        filtered_summary=filtered_summary,
        context=context,
        filters=filters,
        general_state=general_state,
        symbolic_state=symbolic_state,
        summary_sources=summary_sources,
    )
    degradation_roles = _populate_pass_capabilities_and_context(detail_population)
    symbolic_population = SymbolicPopulation(
        filtered_summary=filtered_summary,
        summary=summary,
        pass_results=pass_results,
        by_pass=by_pass,
        degraded_passes=degraded_passes,
        only_degraded=filters.only_degraded,
        summary_sources=summary_sources,
    )
    _populate_filtered_summary_symbolic_sections(symbolic_population)
    _populate_symbolic_issue_passes(symbolic_population)
    _populate_symbolic_coverage_and_severity(symbolic_population)

    filtered_summary["degradation_roles"] = degradation_roles
    for pass_name in filtered_summary["passes"]:
        pass_symbolic_summary = summary_pass_symbolic_summary.get(
            pass_name, pass_results.get(pass_name, {}).get("symbolic_summary")
        )
        if not pass_symbolic_summary:
            normalized_row = normalized_pass_map.get(pass_name, {})
            if normalized_row:
                pass_symbolic_summary = _symbolic_summary_from_normalized_row(pass_name, normalized_row)
        if pass_symbolic_summary:
            filtered_summary["pass_symbolic_summary"][pass_name] = dict(pass_symbolic_summary)

    _fill_pass_map_from_summary(filtered_summary, "pass_validation_context", summary_pass_validation_context)
    _fill_pass_map_from_summary(filtered_summary, "pass_symbolic_summary", summary_pass_symbolic_summary)
    _fill_pass_map_from_summary(filtered_summary, "pass_capabilities", summary_pass_capabilities)

    _populate_triage_and_results(detail_population)
    _populate_pass_evidence(detail_population)
    _apply_risk_filters(
        filtered_summary=filtered_summary,
        selected_risk_pass_names=selected_risk_pass_names,
        only_risky_filters=only_risky_filters,
    )
    _apply_filtered_summary_symbolic_fallback_sections(filtered_summary=filtered_summary, by_pass=by_pass)

    return degradation_roles
