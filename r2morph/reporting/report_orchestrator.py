"""Report orchestration: dispatch between general and mismatch-specific report flows.

Extracted from cli.py -- no logic changes.
"""

from pathlib import Path
from typing import Any

from r2morph.reporting.report_resolver import (
    _resolve_only_mismatches_state,
    _resolve_only_pass_view,
)
from r2morph.reporting.filtered_summary_builder import (
    _build_general_report_payload,
    _build_only_mismatches_payload,
    _build_report_filters,
)
from r2morph.reporting.report_helpers import (
    _finalize_report_output,
    _summary_first,
)
from r2morph.reporting.report_rendering import (
    _render_report_filter_messages,
    _render_only_mismatches_sections,
    _render_symbolic_sections,
    _render_degradation_sections,
    _render_gate_sections,
    _render_pass_capabilities,
    _render_pass_validation_contexts,
    _render_pass_validation_context,
    _render_only_pass_sections,
    _get_console,
)


def _dispatch_report_flow_ctx(ctx: "ReportFlowContext") -> None:
    """Dispatch between general and mismatch-specific report flows.

    Uses ReportFlowContext dataclass to pass structured state instead
    of 43 individual parameters. Sub-dataclasses provide grouped access.
    """
    _render_report_filter_messages(
        only_pass=ctx.filters.only_pass,
        resolved_only_pass=ctx.severity.resolved_only_pass,
        only_pass_failure=ctx.filters.only_pass_failure,
        resolved_only_pass_failure=ctx.severity.resolved_only_pass_failure,
        only_risky_passes=ctx.filters.only_risky_passes,
        only_uncovered_passes=ctx.filters.only_uncovered_passes,
        only_covered_passes=ctx.filters.only_covered_passes,
        only_clean_passes=ctx.filters.only_clean_passes,
        only_structural_risk=ctx.filters.only_structural_risk,
        only_symbolic_risk=ctx.filters.only_symbolic_risk,
        selected_risk_pass_names=ctx.severity.selected_risk_pass_names,
    )
    if ctx.filters.only_mismatches:
        mismatch_state = _resolve_only_mismatches_state(
            summary=ctx.data.summary,
            mutations=ctx.data.mutations,
            filtered_summary=ctx.data.filtered_summary,
            resolved_only_pass=ctx.severity.resolved_only_pass,
            degraded_passes=ctx.validation.degraded_passes,
        )
        _execute_only_mismatches_report_flow(
            payload=ctx.data.payload,
            summary=ctx.data.summary,
            filtered_summary=ctx.data.filtered_summary,
            mismatch_state=mismatch_state,
            pass_support=ctx.data.pass_support,
            requested_validation_mode=ctx.validation.requested_validation_mode,
            effective_validation_mode=ctx.validation.effective_validation_mode,
            degraded_validation=ctx.validation.degraded_validation,
            degraded_passes=ctx.validation.degraded_passes,
            degradation_roles=ctx.validation.degradation_roles,
            failed_gates=ctx.gates.failed_gates,
            gate_evaluation=ctx.gates.gate_evaluation,
            gate_failure_summary=ctx.gates.gate_failure_summary,
            gate_failure_priority=ctx.gates.gate_failure_priority,
            gate_failure_severity_priority=ctx.gates.gate_failure_severity_priority,
            min_severity=ctx.severity.min_severity,
            only_expected_severity=ctx.filters.only_expected_severity,
            resolved_only_pass_failure=ctx.severity.resolved_only_pass_failure,
            validation_policy=ctx.validation.validation_policy,
            resolved_only_pass=ctx.severity.resolved_only_pass,
            only_status=ctx.filters.only_status,
            only_degraded=ctx.filters.only_degraded,
            only_failed_gates=ctx.filters.only_failed_gates,
            only_risky_passes=ctx.filters.only_risky_passes,
            only_uncovered_passes=ctx.filters.only_uncovered_passes,
            only_covered_passes=ctx.filters.only_covered_passes,
            only_clean_passes=ctx.filters.only_clean_passes,
            only_structural_risk=ctx.filters.only_structural_risk,
            only_symbolic_risk=ctx.filters.only_symbolic_risk,
            output=ctx.output.output,
            summary_only=ctx.output.summary_only,
            require_results=ctx.output.require_results,
            min_severity_rank=ctx.severity.min_severity_rank,
        )
        return

    _execute_general_report_flow(
        payload=ctx.data.payload,
        filtered_summary=ctx.data.filtered_summary,
        mutations=ctx.data.mutations,
        summary=ctx.data.summary,
        pass_results=ctx.data.pass_results,
        symbolic_state=ctx.data.symbolic_state,
        degraded_passes=ctx.validation.degraded_passes,
        requested_validation_mode=ctx.validation.requested_validation_mode,
        effective_validation_mode=ctx.validation.effective_validation_mode,
        degraded_validation=ctx.validation.degraded_validation,
        validation_policy=ctx.validation.validation_policy,
        gate_evaluation=ctx.gates.gate_evaluation,
        gate_requested=ctx.gates.gate_requested,
        gate_results=ctx.gates.gate_results,
        gate_failure_summary=ctx.gates.gate_failure_summary,
        gate_failure_priority=ctx.gates.gate_failure_priority,
        gate_failure_severity_priority=ctx.gates.gate_failure_severity_priority,
        degradation_roles=ctx.validation.degradation_roles,
        resolved_only_pass=ctx.severity.resolved_only_pass,
        only_status=ctx.filters.only_status,
        only_degraded=ctx.filters.only_degraded,
        only_failed_gates=ctx.filters.only_failed_gates,
        only_risky_passes=ctx.filters.only_risky_passes,
        only_uncovered_passes=ctx.filters.only_uncovered_passes,
        only_covered_passes=ctx.filters.only_covered_passes,
        only_clean_passes=ctx.filters.only_clean_passes,
        only_structural_risk=ctx.filters.only_structural_risk,
        only_symbolic_risk=ctx.filters.only_symbolic_risk,
        min_severity=ctx.severity.min_severity,
        only_expected_severity=ctx.filters.only_expected_severity,
        resolved_only_pass_failure=ctx.severity.resolved_only_pass_failure,
        output=ctx.output.output,
        summary_only=ctx.output.summary_only,
        require_results=ctx.output.require_results,
        min_severity_rank=ctx.severity.min_severity_rank,
        failed_gates=ctx.gates.failed_gates,
    )


def _dispatch_report_flow(**kwargs: Any) -> None:
    """Backward-compatible wrapper that constructs ReportFlowContext from kwargs."""
    from r2morph.reporting.report_context import (
        FilterFlags,
        GateState,
        OutputConfig,
        ReportFlowContext,
        ReportPayload,
        SeverityFilter,
        ValidationState,
    )

    ctx = ReportFlowContext(
        data=ReportPayload(
            payload=kwargs.get("payload", {}),
            summary=kwargs.get("summary", {}),
            filtered_summary=kwargs.get("filtered_summary", {}),
            mutations=kwargs.get("mutations", []),
            pass_results=kwargs.get("pass_results", {}),
            pass_support=kwargs.get("pass_support", {}),
            symbolic_state=kwargs.get("symbolic_state", {}),
        ),
        validation=ValidationState(
            requested_validation_mode=kwargs.get("requested_validation_mode"),
            effective_validation_mode=kwargs.get("effective_validation_mode"),
            degraded_validation=kwargs.get("degraded_validation", False),
            degraded_passes=kwargs.get("degraded_passes", []),
            degradation_roles=kwargs.get("degradation_roles", {}),
            validation_policy=kwargs.get("validation_policy"),
        ),
        gates=GateState(
            failed_gates=kwargs.get("failed_gates", False),
            gate_evaluation=kwargs.get("gate_evaluation", {}),
            gate_requested=kwargs.get("gate_requested", {}),
            gate_results=kwargs.get("gate_results", {}),
            gate_failure_summary=kwargs.get("gate_failure_summary", {}),
            gate_failure_priority=kwargs.get("gate_failure_priority", []),
            gate_failure_severity_priority=kwargs.get("gate_failure_severity_priority", []),
        ),
        filters=FilterFlags(
            only_mismatches=kwargs.get("only_mismatches", False),
            only_status=kwargs.get("only_status"),
            only_degraded=kwargs.get("only_degraded", False),
            only_failed_gates=kwargs.get("only_failed_gates", False),
            only_risky_passes=kwargs.get("only_risky_passes", False),
            only_structural_risk=kwargs.get("only_structural_risk", False),
            only_symbolic_risk=kwargs.get("only_symbolic_risk", False),
            only_uncovered_passes=kwargs.get("only_uncovered_passes", False),
            only_covered_passes=kwargs.get("only_covered_passes", False),
            only_clean_passes=kwargs.get("only_clean_passes", False),
            only_pass=kwargs.get("only_pass"),
            only_pass_failure=kwargs.get("only_pass_failure"),
            only_expected_severity=kwargs.get("only_expected_severity"),
        ),
        severity=SeverityFilter(
            min_severity=kwargs.get("min_severity"),
            min_severity_rank=kwargs.get("min_severity_rank"),
            resolved_only_pass=kwargs.get("resolved_only_pass"),
            resolved_only_pass_failure=kwargs.get("resolved_only_pass_failure"),
            selected_risk_pass_names=kwargs.get("selected_risk_pass_names", set()),
        ),
        output=OutputConfig(
            output=kwargs.get("output"),
            summary_only=kwargs.get("summary_only", False),
            require_results=kwargs.get("require_results", False),
        ),
    )
    _dispatch_report_flow_ctx(ctx)


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
        pass_region_evidence=pass_region_evidence,
        pass_capabilities=capability_row,
    )


