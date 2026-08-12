"""Pure mutation-selection helpers for report filtering."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_builder_models import ReportContext
from r2morph.reporting.report_context import FilterFlags


def _select_report_mutations(
    all_mutations: list[dict[str, Any]],
    context: ReportContext,
    filters: FilterFlags,
    selected_risk_pass_names: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Apply report filters to mutations and degraded pass rows."""
    mutations = list(all_mutations)
    adjusted_degraded_passes = list(context.degraded_passes)
    only_risky_filters = filters.pass_classes.any_active
    if filters.only_degraded and not context.degraded_validation:
        mutations = []
    if filters.only_failed_gates and not context.failed_gates:
        mutations = []
    if only_risky_filters:
        mutations = [mutation for mutation in mutations if mutation.get("pass_name") in selected_risk_pass_names]
    if context.resolved_only_pass and adjusted_degraded_passes:
        adjusted_degraded_passes = [
            item
            for item in adjusted_degraded_passes
            if item.get("pass_name") == context.resolved_only_pass or item.get("mutation") == context.resolved_only_pass
        ]
    if only_risky_filters and adjusted_degraded_passes:
        adjusted_degraded_passes = [
            item
            for item in adjusted_degraded_passes
            if item.get("pass_name", item.get("mutation", "unknown")) in selected_risk_pass_names
        ]
    if context.resolved_only_pass:
        mutations = [mutation for mutation in mutations if mutation.get("pass_name") == context.resolved_only_pass]
    if filters.only_status:
        mutations = [
            mutation
            for mutation in mutations
            if mutation.get("metadata", {}).get("symbolic_status") == filters.only_status
        ]
    return mutations, adjusted_degraded_passes
