"""Report resolver: pure data logic for resolving report state.

Extracted from cli.py -- no logic changes.
"""

from typing import Any

from r2morph.reporting.report_helpers import (
    _select_report_mutations,
    _summarize_symbolic_view_from_mutations,
)
from r2morph.reporting.report_mismatch_state import (
    resolve_only_mismatches_state as _resolve_only_mismatches_state_impl,
)
from r2morph.reporting.report_pass_resolution import resolve_only_pass_view
from r2morph.reporting.report_rendering_sections import (
    _render_symbolic_sections as _render_symbolic_sections_impl,
)
from r2morph.reporting.report_state import (
    resolve_general_symbolic_state as _resolve_general_symbolic_state_impl,
)
from r2morph.reporting.report_state import (
    resolve_pass_filter_sets as _resolve_pass_filter_sets_impl,
)


def _resolve_general_report_flow_state(
    *,
    payload: dict[str, Any],
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    degraded_passes: list[dict[str, Any]],
    failed_gates: bool,
    validation_policy: dict[str, Any] | None,
    gate_evaluation: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    resolved_only_pass: str | None,
    only_status: str | None,
    only_degraded: bool,
    only_failed_gates: bool,
    only_risky_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    summary_builder: Any = None,
) -> dict[str, Any]:
    """Resolve summary-first state for the general report path.

    Args:
        summary_builder: Callable with same signature as _build_general_filtered_summary.
            Injected to avoid circular import between resolver and filtered_summary_builder.
    """
    general_state = _resolve_general_report_state(
        summary=summary,
        payload=payload,
        pass_results=pass_results,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_risky_passes=only_risky_passes,
    )
    only_risky_filters = (
        only_risky_passes
        or only_structural_risk
        or only_symbolic_risk
        or only_uncovered_passes
        or only_covered_passes
        or only_clean_passes
    )
    mutations, adjusted_degraded_passes = _select_report_mutations(
        all_mutations=payload.get("mutations", []),
        degraded_validation=degraded_validation,
        failed_gates=failed_gates,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_filters=only_risky_filters,
        selected_risk_pass_names=general_state["selected_risk_pass_names"],
        resolved_only_pass=resolved_only_pass,
        only_status=only_status,
        degraded_passes=degraded_passes,
    )
    symbolic_state = _resolve_general_symbolic_state_impl(
        summary=summary,
        mutations=mutations,
        pass_results=pass_results,
        summarize_symbolic_func=_summarize_symbolic_view_from_mutations,
        render_symbolic_func=_render_symbolic_sections_impl,
    )
    if summary_builder is None:
        from r2morph.reporting.filtered_summary_builder import _build_general_filtered_summary

        summary_builder = _build_general_filtered_summary
    filtered_summary, degradation_roles = summary_builder(
        summary=summary,
        mutations=mutations,
        pass_results=pass_results,
        pass_support=general_state["pass_support"],
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        degraded_passes=adjusted_degraded_passes,
        risky_pass_names=general_state["risky_pass_names"],
        structural_risk_pass_names=general_state["structural_risk_pass_names"],
        symbolic_risk_pass_names=general_state["symbolic_risk_pass_names"],
        covered_pass_names=general_state["covered_pass_names"],
        uncovered_pass_names=general_state["uncovered_pass_names"],
        clean_pass_names=general_state["clean_pass_names"],
        failed_gates=failed_gates,
        validation_policy=validation_policy,
        gate_evaluation=gate_evaluation,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
        symbolic_requested=symbolic_state["symbolic_requested"],
        observable_match=symbolic_state["observable_match"],
        observable_mismatch=symbolic_state["observable_mismatch"],
        bounded_only=symbolic_state["bounded_only"],
        observable_not_run=symbolic_state["observable_not_run"],
        by_pass=symbolic_state["by_pass"],
        degradation_roles=dict(summary.get("degradation_roles", {})),
        normalized_pass_map=symbolic_state["normalized_pass_map"],
        selected_risk_pass_names=general_state["selected_risk_pass_names"],
        resolved_only_pass=resolved_only_pass,
        only_risky_filters=only_risky_filters,
        only_degraded=only_degraded,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        only_failed_gates=only_failed_gates,
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
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_risky_passes: bool,
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
    if only_uncovered_passes:
        selected_risk_pass_names = uncovered_pass_names
    elif only_covered_passes:
        selected_risk_pass_names = covered_pass_names
    elif only_clean_passes:
        selected_risk_pass_names = clean_pass_names
    elif only_structural_risk and only_symbolic_risk:
        selected_risk_pass_names = structural_risk_pass_names & symbolic_risk_pass_names
    elif only_structural_risk:
        selected_risk_pass_names = structural_risk_pass_names
    elif only_symbolic_risk:
        selected_risk_pass_names = symbolic_risk_pass_names
    elif only_risky_passes:
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
