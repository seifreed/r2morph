"""Pass metadata and evidence population helpers for filtered summaries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from r2morph.reporting.report_builder_models import ReportContext
from r2morph.reporting.report_context import FilterFlags
from r2morph.reporting.report_evidence_sorting import _sort_pass_evidence
from r2morph.reporting.report_helpers import (
    _pass_evidence_from_row,
    _validation_context_from_role,
)


@dataclass(frozen=True)
class PassDetailPopulation:
    """Shared state for pass capability, context, and evidence population."""

    filtered_summary: dict[str, Any]
    context: ReportContext
    filters: FilterFlags
    general_state: dict[str, Any]
    symbolic_state: dict[str, Any]
    summary_sources: dict[str, Any]


def _populate_pass_capabilities_and_context(state: PassDetailPopulation) -> dict[str, int]:
    """Populate pass_capabilities and pass_validation_context for each visible pass."""
    filtered_summary = state.filtered_summary
    pass_results = state.symbolic_state["pass_results"]
    pass_support = state.general_state["pass_support"]
    normalized_pass_map = state.symbolic_state["normalized_pass_map"]
    summary_pass_capabilities = state.summary_sources["pass_capabilities"]
    summary_pass_validation_context = state.summary_sources["pass_validation_context"]
    for pass_name in filtered_summary["passes"]:
        capabilities = summary_pass_capabilities.get(pass_name)
        if capabilities is None:
            normalized_row = normalized_pass_map.get(pass_name, {})
            if normalized_row:
                capabilities = {
                    "runtime": {"recommended": bool(normalized_row.get("runtime_recommended", False))},
                    "symbolic": {
                        "recommended": bool(normalized_row.get("symbolic_recommended", False)),
                        "confidence": normalized_row.get("symbolic_confidence", "unknown"),
                    },
                }
        if capabilities is None:
            support = pass_support.get(pass_name)
            if support:
                capabilities = support.get("validator_capabilities", {})
        if capabilities:
            filtered_summary["pass_capabilities"][pass_name] = dict(capabilities)

        context = summary_pass_validation_context.get(
            pass_name, pass_results.get(pass_name, {}).get("validation_context")
        )
        if not context:
            normalized_row = normalized_pass_map.get(pass_name, {})
            if normalized_row:
                context = _validation_context_from_role(
                    normalized_row.get("role", "requested-mode"),
                    state.context.requested_validation_mode,
                    state.context.effective_validation_mode,
                )
        if context:
            context_payload = dict(context)
            context_payload["role"] = (
                "degradation-trigger"
                if context.get("degradation_triggered_by_pass")
                else "executed-under-degraded-mode" if context.get("degraded_execution") else "requested-mode"
            )
            filtered_summary["pass_validation_context"][pass_name] = context_payload

    degradation_roles = dict(state.context.summary.get("degradation_roles", {}))
    if not degradation_roles:
        for context in filtered_summary["pass_validation_context"].values():
            role = context.get("role")
            if role:
                degradation_roles[role] = degradation_roles.get(role, 0) + 1
    return degradation_roles


def _populate_pass_evidence(state: PassDetailPopulation) -> None:
    """Populate pass_evidence and pass_region_evidence_map with fallback chains."""
    filtered_summary = state.filtered_summary
    pass_results = state.symbolic_state["pass_results"]
    normalized_pass_map = state.symbolic_state["normalized_pass_map"]
    selected_risk_pass_names = state.general_state["selected_risk_pass_names"]
    summary_pass_region_evidence_map = state.summary_sources["pass_region_evidence_map"]
    summary_pass_evidence_map = state.summary_sources["pass_evidence_map"]
    summary_general_pass_rows = state.summary_sources["general_pass_rows"]
    visible_passes = set(filtered_summary["passes"])
    if summary_pass_region_evidence_map:
        filtered_summary["pass_region_evidence_map"] = {
            pass_name: list(rows)
            for pass_name, rows in summary_pass_region_evidence_map.items()
            if not visible_passes or pass_name in visible_passes
        }
    if not filtered_summary["pass_evidence"]:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                dict(pass_results.get(pass_name, {}).get("evidence_summary", {}))
                for pass_name in filtered_summary["passes"]
                if pass_results.get(pass_name, {}).get("evidence_summary")
            ]
        )
    if not filtered_summary["pass_evidence"] and summary_pass_evidence_map:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                dict(row)
                for pass_name, row in summary_pass_evidence_map.items()
                if (not visible_passes or pass_name in visible_passes) and row.get("pass_name")
            ]
        )
    if not filtered_summary["pass_evidence"] and summary_general_pass_rows:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                _pass_evidence_from_row(row.get("pass_name"), row)
                for row in summary_general_pass_rows
                if row.get("pass_name") and (not visible_passes or row.get("pass_name") in visible_passes)
            ]
        )
    if not filtered_summary["pass_evidence"] and filtered_summary["normalized_pass_results"]:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                _pass_evidence_from_row(row.get("pass_name"), row)
                for row in filtered_summary["normalized_pass_results"]
                if row.get("pass_name")
            ]
        )
    if not filtered_summary["pass_evidence"] and normalized_pass_map:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                _pass_evidence_from_row(pass_name, row)
                for pass_name, row in normalized_pass_map.items()
                if pass_name in set(filtered_summary["passes"])
            ]
        )
    if state.filters.pass_classes.any_active and not filtered_summary["pass_evidence"]:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                dict(pass_results.get(pass_name, {}).get("evidence_summary", {}))
                for pass_name in sorted(selected_risk_pass_names)
                if pass_results.get(pass_name, {}).get("evidence_summary")
                and (state.context.resolved_only_pass is None or pass_name == state.context.resolved_only_pass)
            ]
        )
