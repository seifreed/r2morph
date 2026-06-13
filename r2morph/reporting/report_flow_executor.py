"""Report flow execution helpers extracted from report_orchestrator."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from r2morph.reporting.filtered_summary_builder import (
    _build_general_report_payload,
    _build_only_mismatches_payload,
    _build_report_filters,
)
from r2morph.reporting.report_output_policy import _finalize_report_output
from r2morph.reporting.report_rendering_sections import (
    _render_degradation_sections,
    _render_gate_sections,
    _render_only_mismatches_sections,
    _render_only_pass_sections,
    _render_pass_capabilities,
    _render_pass_validation_contexts,
    _render_symbolic_sections,
)
from r2morph.reporting.report_resolver import _resolve_only_pass_view


def _execute_general_report_flow(
    *,
    payload: dict[str, Any],
    filtered_summary: dict[str, Any],
    mutations: list[dict[str, Any]],
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
    only_status: str | None,
    only_degraded: bool,
    only_failed_gates: bool,
    only_risky_passes: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    min_severity: str | None,
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
    output: Path | None,
    summary_only: bool,
    require_results: bool,
    min_severity_rank: int | None,
    failed_gates: bool,
) -> None:
    """Render and emit the general report path."""
    _render_general_flow_sections(
        filtered_summary=filtered_summary,
        summary=summary,
        pass_results=pass_results,
        symbolic_state=symbolic_state,
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
        resolved_only_pass=resolved_only_pass,
    )
    filtered_payload = _build_general_report_payload(
        payload=payload,
        mutations=mutations,
        filtered_summary=filtered_summary,
        resolved_only_pass=resolved_only_pass,
        only_status=only_status,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_passes=only_risky_passes,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        min_severity=min_severity,
        only_expected_severity=only_expected_severity,
        resolved_only_pass_failure=resolved_only_pass_failure,
    )
    _finalize_report_output(
        filtered_payload=filtered_payload,
        output=output,
        summary_only=summary_only,
        require_results=require_results,
        min_severity_rank=min_severity_rank,
        only_failed_gates=only_failed_gates,
        failed_gates=failed_gates,
        only_expected_severity=only_expected_severity,
        resolved_only_pass_failure=resolved_only_pass_failure,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
    )


def _execute_only_mismatches_report_flow(
    *,
    payload: dict[str, Any],
    summary: dict[str, Any],
    filtered_summary: dict[str, Any],
    mismatch_state: dict[str, Any],
    pass_support: dict[str, Any],
    requested_validation_mode: str,
    effective_validation_mode: str,
    degraded_validation: bool,
    degraded_passes: list[dict[str, Any]],
    degradation_roles: dict[str, int],
    failed_gates: bool,
    gate_evaluation: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    min_severity: str | None,
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
    validation_policy: dict[str, Any] | None,
    resolved_only_pass: str | None,
    only_status: str | None,
    only_degraded: bool,
    only_failed_gates: bool,
    only_risky_passes: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    output: Path | None,
    summary_only: bool,
    require_results: bool,
    min_severity_rank: int | None,
) -> None:
    """Render and emit the `report --only-mismatches` path."""
    _render_only_mismatches_sections(
        filtered_mutations=mismatch_state["filtered_mutations"],
        filtered_passes=mismatch_state["filtered_passes"],
        mismatch_counts_by_pass=mismatch_state["mismatch_counts_by_pass"],
        mismatch_observables_by_pass=mismatch_state["mismatch_observables_by_pass"],
        mismatch_pass_context=mismatch_state["mismatch_pass_context"],
        mismatch_degraded_passes=mismatch_state["mismatch_degraded_passes"],
        degraded_passes=degraded_passes,
        degraded_validation=degraded_validation,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        mismatch_severity_rows=mismatch_state["mismatch_severity_rows"],
    )
    filtered_payload = _build_only_mismatches_payload(
        payload=payload,
        summary=summary,
        filtered_summary=filtered_summary,
        filtered_mutations=mismatch_state["filtered_mutations"],
        filtered_passes=mismatch_state["filtered_passes"],
        mismatch_counts_by_pass=mismatch_state["mismatch_counts_by_pass"],
        mismatch_observables_by_pass=mismatch_state["mismatch_observables_by_pass"],
        persisted_mismatch_priority=mismatch_state["persisted_mismatch_priority"],
        mismatch_severity_rows=mismatch_state["mismatch_severity_rows"],
        mismatch_pass_context=mismatch_state["mismatch_pass_context"],
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        mismatch_degraded_passes=mismatch_state["mismatch_degraded_passes"],
        degraded_passes=degraded_passes,
        degradation_roles=degradation_roles,
        failed_gates=failed_gates,
        pass_support=pass_support,
        gate_evaluation=gate_evaluation,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
        min_severity=min_severity,
        only_expected_severity=only_expected_severity,
        resolved_only_pass_failure=resolved_only_pass_failure,
        validation_policy=validation_policy,
    )
    filtered_payload["report_filters"] = _build_report_filters(
        resolved_only_pass=resolved_only_pass,
        only_status=only_status,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_passes=only_risky_passes,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_mismatches=True,
        min_severity=min_severity,
        only_expected_severity=only_expected_severity,
        resolved_only_pass_failure=resolved_only_pass_failure,
    )
    _finalize_report_output(
        filtered_payload=filtered_payload,
        output=output,
        summary_only=summary_only,
        require_results=require_results,
        min_severity_rank=min_severity_rank,
        only_failed_gates=only_failed_gates,
        failed_gates=failed_gates,
        only_expected_severity=only_expected_severity,
        resolved_only_pass_failure=resolved_only_pass_failure,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
    )


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
