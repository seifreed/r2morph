"""Rendering helpers for report flow execution."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_rendering_sections import (
    _render_degradation_sections,
    _render_gate_sections,
    _render_only_pass_sections,
    _render_pass_capabilities,
    _render_pass_validation_contexts,
    _render_symbolic_sections,
)
from r2morph.reporting.report_rendering_sections import (
    _render_only_mismatches_sections as _render_only_mismatches_sections_impl,
)
from r2morph.reporting.report_resolver import _resolve_only_pass_view


def _render_general_flow_sections(
    *,
    filtered_summary: dict[str, Any],
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    symbolic_state: dict[str, Any],
    degraded_passes: list[dict[str, Any]],
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    validation_policy: dict[str, Any] | None,
    gate_evaluation: dict[str, Any],
    gate_requested: dict[str, Any],
    gate_results: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    degradation_roles: dict[str, int],
    resolved_only_pass: str | None,
) -> None:
    """Render the general report sections before output emission."""
    _render_general_report_sections(
        filtered_summary=filtered_summary,
        pass_results=pass_results,
        degraded_passes=degraded_passes,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        validation_policy=validation_policy,
        gate_evaluation=gate_evaluation,
        gate_requested=gate_requested,
        gate_results=gate_results,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
        degradation_roles=degradation_roles,
    )
    _render_general_only_pass_sections(
        summary=summary,
        filtered_summary=filtered_summary,
        pass_results=pass_results,
        resolved_only_pass=resolved_only_pass,
    )
    _render_symbolic_sections(
        symbolic_requested=symbolic_state.get("symbolic_requested", 0),
        observable_match=symbolic_state.get("observable_match", 0),
        observable_mismatch=symbolic_state.get("observable_mismatch", 0),
        bounded_only=symbolic_state.get("bounded_only", 0),
        observable_not_run=symbolic_state.get("observable_not_run", 0),
        summary=filtered_summary,
        pass_results=pass_results,
        by_pass=symbolic_state.get("by_pass", {}),
        mismatch_rows=symbolic_state.get("mismatch_rows", []),
    )


def _render_general_report_sections(
    *,
    filtered_summary: dict[str, Any],
    pass_results: dict[str, Any],
    degraded_passes: list[dict[str, Any]],
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    validation_policy: dict[str, Any] | None,
    gate_evaluation: dict[str, Any],
    gate_requested: dict[str, Any],
    gate_results: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    degradation_roles: dict[str, int],
) -> None:
    """Render the general non-mismatch report sections."""
    degraded_severity_rows = [
        row
        for row in filtered_summary["symbolic_severity_by_pass"]
        if row.get("pass_name") in {item.get("pass_name", item.get("mutation", "unknown")) for item in degraded_passes}
    ]
    _render_degradation_sections(
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        validation_policy=validation_policy,
        degraded_passes=degraded_passes,
        degradation_roles=degradation_roles,
        symbolic_severity_rows=degraded_severity_rows,
    )
    if gate_evaluation:
        _render_gate_sections(
            gate_evaluation=gate_evaluation,
            gate_requested=gate_requested,
            gate_results=gate_results,
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=filtered_summary.get("gate_failure_priority", []) or gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
        )
    _render_pass_capabilities(filtered_summary=filtered_summary)
    if pass_results:
        _render_pass_validation_contexts(
            filtered_summary=filtered_summary,
            pass_results=pass_results,
            degraded_passes=degraded_passes,
        )


def _render_general_only_pass_sections(
    *,
    summary: dict[str, Any],
    filtered_summary: dict[str, Any],
    pass_results: dict[str, Any],
    resolved_only_pass: str | None,
) -> None:
    """Render single-pass sections for the general report flow."""
    if not resolved_only_pass:
        return
    (
        pass_symbolic_summary,
        pass_evidence,
        pass_validation_context,
        pass_region_evidence,
    ) = _resolve_only_pass_view(
        summary=summary,
        filtered_summary=filtered_summary,
        pass_results=pass_results,
        pass_name=resolved_only_pass,
    )
    capability_map = dict(summary.get("pass_capability_summary_map", {}) or {})
    capability_row = filtered_summary.get("pass_capability_summary", {})
    if isinstance(capability_row, list):
        capability_row = next(
            (row for row in capability_row if row.get("pass_name") == resolved_only_pass),
            None,
        )
    elif isinstance(capability_row, dict):
        capability_row = capability_row.get(resolved_only_pass)
    if capability_row is None:
        capability_row = capability_map.get(resolved_only_pass)
    if capability_row is None:
        capability_row = (
            dict(summary.get("report_views", {}) or {})
            .get("only_pass", {})
            .get(resolved_only_pass, {})
            .get("capabilities")
        )
    _render_only_pass_sections(
        pass_name=resolved_only_pass,
        pass_symbolic_summary=pass_symbolic_summary,
        pass_evidence=pass_evidence,
        pass_validation_context=pass_validation_context,
        pass_region_evidence=pass_region_evidence if pass_region_evidence else None,
        pass_capabilities=capability_row,
    )


def _render_only_mismatches_sections(
    *,
    filtered_mutations: list[dict[str, Any]],
    filtered_passes: list[str],
    mismatch_counts_by_pass: dict[str, int],
    mismatch_observables_by_pass: dict[str, list[str]],
    mismatch_pass_context: dict[str, Any],
    mismatch_degraded_passes: list[dict[str, Any]],
    degraded_passes: list[dict[str, Any]],
    degraded_validation: bool,
    requested_validation_mode: str,
    effective_validation_mode: str,
    mismatch_severity_rows: list[dict[str, Any]],
) -> None:
    """Render the textual sections for report --only-mismatches."""
    _render_only_mismatches_sections_impl(
        filtered_mutations=filtered_mutations,
        filtered_passes=filtered_passes,
        mismatch_counts_by_pass=mismatch_counts_by_pass,
        mismatch_observables_by_pass=mismatch_observables_by_pass,
        mismatch_pass_context=mismatch_pass_context,
        mismatch_degraded_passes=mismatch_degraded_passes,
        degraded_passes=degraded_passes,
        degraded_validation=degraded_validation,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        mismatch_severity_rows=mismatch_severity_rows,
    )
