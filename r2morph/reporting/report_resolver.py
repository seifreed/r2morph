"""Report resolver: pure data logic for resolving report state.

Extracted from cli.py -- no logic changes.
"""

import re
from typing import Any

from r2morph.core.engine import (
    _build_gate_failure_severity_priority,
    _summarize_gate_failures,
)
from r2morph.reporting.report_helpers import (
    _is_risky_pass,
    _has_structural_risk,
    _has_symbolic_risk,
    _is_clean_pass,
    _is_covered_pass,
    _is_uncovered_pass,
    _pass_names_from_triage_rows,
    _select_report_mutations,
    _summarize_symbolic_view_from_mutations,
    _sort_pass_evidence,
    _filter_failed_gates_view,
    _expected_severity_rank_from_failure,
    _normalized_pass_map,
    _summary_first,
    _visible_rows,
    _resolve_general_report_views,
    _resolve_summary_pass_sources,
)


def _resolve_pass_filter_sets(
    *,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
) -> dict[str, set[str]]:
    """Resolve pass filter buckets from persisted summary first, then fall back."""
    report_views = dict(summary.get("report_views", {}) or {})
    general_renderer_state = dict(report_views.get("general_renderer_state", {}) or {})
    pass_filter_views = dict(report_views.get("general_filter_views", report_views.get("pass_filter_views", {})) or {})
    if not pass_filter_views and general_renderer_state.get("general_filter_views"):
        pass_filter_views = {
            f"only_{key}_passes"
            if key in {"risky", "clean", "covered", "uncovered"}
            else "only_structural_risk"
            if key == "structural_risk"
            else "only_symbolic_risk"
            if key == "symbolic_risk"
            else key: value
            for key, value in dict(general_renderer_state.get("general_filter_views", {}) or {}).items()
        }
    if not pass_filter_views and general_renderer_state.get("filter_views"):
        pass_filter_views = {
            f"only_{key}_passes"
            if key in {"risky", "clean", "covered", "uncovered"}
            else "only_structural_risk"
            if key == "structural_risk"
            else "only_symbolic_risk"
            if key == "symbolic_risk"
            else key: value
            for key, value in dict(general_renderer_state.get("filter_views", {}) or {}).items()
        }
    risk_buckets = dict(
        _summary_first(
            summary,
            "pass_risk_buckets",
            pass_filter_views or report_views.get("passes", {}),
        )
        or {}
    )
    coverage_buckets = dict(
        _summary_first(
            summary,
            "pass_coverage_buckets",
            {
                "covered": (pass_filter_views or report_views.get("passes", {})).get("covered", []),
                "uncovered": (pass_filter_views or report_views.get("passes", {})).get("uncovered", []),
                "clean_only": (pass_filter_views or report_views.get("passes", {})).get("clean", []),
            },
        )
        or {}
    )
    triage_rows = list(
        _summary_first(
            summary,
            "pass_triage_rows",
            report_views.get("general_triage_rows", report_views.get("triage_priority", [])),
        )
        or []
    )
    if not triage_rows and general_renderer_state.get("triage_rows"):
        triage_rows = list(general_renderer_state.get("triage_rows", []) or [])
    resolved = {
        "risky": set(pass_filter_views.get("only_risky_passes", risk_buckets.get("risky", []))),
        "structural": set(
            pass_filter_views.get(
                "only_structural_risk",
                risk_buckets.get("structural", []),
            )
        ),
        "symbolic": set(pass_filter_views.get("only_symbolic_risk", risk_buckets.get("symbolic", []))),
        "clean": set(pass_filter_views.get("only_clean_passes", risk_buckets.get("clean", []))),
        "covered": set(
            pass_filter_views.get(
                "only_covered_passes",
                coverage_buckets.get("covered", []),
            )
        ),
        "uncovered": set(
            pass_filter_views.get(
                "only_uncovered_passes",
                coverage_buckets.get("uncovered", []),
            )
        ),
    }
    if triage_rows:
        for kind in ("risky", "structural", "symbolic", "clean", "covered", "uncovered"):
            if not resolved[kind]:
                resolved[kind] = _pass_names_from_triage_rows(triage_rows, kind=kind)
    summary_pass_evidence = list(_summary_first(summary, "pass_evidence", []))
    fallback_checks = {
        "risky": lambda row, symbolic: _is_risky_pass(row, symbolic),
        "structural": lambda row, symbolic: _has_structural_risk(row),
        "symbolic": lambda row, symbolic: _has_symbolic_risk(row, symbolic),
        "clean": lambda row, symbolic: _is_clean_pass(row, symbolic),
        "covered": lambda row, symbolic: _is_covered_pass(row, symbolic),
        "uncovered": lambda row, symbolic: _is_uncovered_pass(row, symbolic),
    }
    for kind, predicate in fallback_checks.items():
        if resolved[kind]:
            continue
        matches = {
            pass_name
            for pass_name, pass_result in pass_results.items()
            if predicate(
                pass_result.get("evidence_summary"),
                pass_result.get("symbolic_summary"),
            )
        }
        if not matches and summary_pass_evidence:
            matches = {
                str(row.get("pass_name"))
                for row in summary_pass_evidence
                if row.get("pass_name")
                and predicate(
                    row,
                    pass_results.get(str(row.get("pass_name")), {}).get("symbolic_summary"),
                )
            }
        resolved[kind] = matches
    return resolved


def _resolve_mismatch_view(
    *,
    summary: dict[str, Any],
    filtered_mutations: list[dict[str, Any]],
) -> tuple[dict[str, int], dict[str, list[str]], list[dict[str, Any]]]:
    """Resolve mismatch counts/observables/priority from persisted summary first."""
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
    for mutation in filtered_mutations:
        pass_name = mutation.get("pass_name", "unknown")
        counts_by_pass[pass_name] = counts_by_pass.get(pass_name, 0) + 1
        mismatch_observables = mutation.get("metadata", {}).get("symbolic_observable_mismatches", [])
        if mismatch_observables:
            merged = set(observables_by_pass.get(pass_name, []))
            merged.update(mismatch_observables)
            observables_by_pass[pass_name] = sorted(merged)
    return counts_by_pass, observables_by_pass, mismatch_priority or mismatch_view


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
) -> dict[str, Any]:
    """Resolve summary-first state for the general report path."""
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
    symbolic_state = _resolve_general_symbolic_state(
        summary=summary,
        mutations=mutations,
        pass_results=pass_results,
    )
    from r2morph.reporting.report_builder_ext import _build_general_filtered_summary
    filtered_summary, degradation_roles = _build_general_filtered_summary(
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
    """Resolve summary-first state for the `report --only-mismatches` path."""
    report_views = dict(summary.get("report_views", {}) or {})
    persisted_mismatch_view = dict(report_views.get("only_mismatches", {}) or {})
    filtered_mutations = [
        mutation
        for mutation in mutations
        if mutation.get("metadata", {}).get("symbolic_observable_check_performed")
        and not mutation.get("metadata", {}).get("symbolic_observable_equivalent", False)
    ]
    mismatch_counts_by_pass, mismatch_observables_by_pass, persisted_mismatch_priority = _resolve_mismatch_view(
        summary=summary, filtered_mutations=filtered_mutations
    )
    filtered_passes = sorted(
        {
            pass_name
            for pass_name, count in mismatch_counts_by_pass.items()
            if count > 0 and (resolved_only_pass is None or pass_name == resolved_only_pass)
        }
    )
    if not filtered_passes:
        filtered_passes = sorted(
            {
                str(row.get("pass_name"))
                for row in list(persisted_mismatch_view.get("compact_rows", []) or [])
                if row.get("pass_name") and (resolved_only_pass is None or row.get("pass_name") == resolved_only_pass)
            }
        )
    mismatch_pass_context = {}
    for pass_name in filtered_passes:
        context = filtered_summary["pass_validation_context"].get(pass_name)
        if context:
            mismatch_pass_context[pass_name] = context
    mismatch_degraded_passes = list(degraded_passes)
    if filtered_passes and mismatch_degraded_passes:
        mismatch_degraded_passes = [
            item
            for item in mismatch_degraded_passes
            if item.get("pass_name", item.get("mutation", "unknown")) in filtered_passes
        ]
    mismatch_severity_rows = _resolve_mismatch_severity_rows(
        summary=summary,
        filtered_summary=filtered_summary,
        filtered_passes=filtered_passes,
        mismatch_degraded_passes=mismatch_degraded_passes,
        mismatch_counts_by_pass=mismatch_counts_by_pass,
    )
    return {
        "filtered_mutations": filtered_mutations,
        "mismatch_counts_by_pass": mismatch_counts_by_pass,
        "mismatch_observables_by_pass": mismatch_observables_by_pass,
        "persisted_mismatch_priority": persisted_mismatch_priority,
        "filtered_passes": filtered_passes,
        "mismatch_pass_context": mismatch_pass_context,
        "mismatch_degraded_passes": mismatch_degraded_passes,
        "mismatch_severity_rows": mismatch_severity_rows,
    }


def _resolve_general_filtered_passes(
    *,
    existing_passes: list[str],
    summary_only_pass_view: dict[str, Any],
    summary_general_passes: list[dict[str, Any]],
    summary_general_pass_rows: list[dict[str, Any]],
    summary_general_summary: dict[str, Any],
    resolved_only_pass: str | None,
    selected_risk_pass_names: set[str],
    only_risky_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_failed_gates: bool,
    gate_failure_priority: list[dict[str, Any]],
) -> list[str]:
    """Resolve the visible pass list for the general report path."""
    resolved_passes = list(existing_passes)
    if not resolved_passes and summary_general_summary.get("passes"):
        resolved_passes = [str(pass_name) for pass_name in list(summary_general_summary.get("passes", [])) if pass_name]
    if not resolved_passes and summary_general_passes:
        resolved_passes = sorted({str(row.get("pass_name")) for row in summary_general_passes if row.get("pass_name")})
    if not resolved_passes and summary_general_pass_rows:
        resolved_passes = sorted(
            {str(row.get("pass_name")) for row in summary_general_pass_rows if row.get("pass_name")}
        )
    if resolved_only_pass and not resolved_passes and resolved_only_pass in summary_only_pass_view:
        resolved_passes = [resolved_only_pass]
    if (
        only_risky_passes
        or only_structural_risk
        or only_symbolic_risk
        or only_uncovered_passes
        or only_covered_passes
        or only_clean_passes
    ):
        return sorted(
            pass_name
            for pass_name in selected_risk_pass_names
            if resolved_only_pass is None or pass_name == resolved_only_pass
        )
    if resolved_only_pass and not resolved_passes:
        return [resolved_only_pass]
    if only_failed_gates and not resolved_passes and gate_failure_priority:
        return sorted({str(row.get("pass_name")) for row in gate_failure_priority if row.get("pass_name")})
    return resolved_passes


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
    pass_filter_sets = _resolve_pass_filter_sets(summary=summary, pass_results=pass_results)
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


def _resolve_failed_gates_view(
    *,
    summary: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve failed-gates summary and ordering from persisted report views first."""
    report_views = dict(summary.get("report_views", {}) or {})
    failed_gates_view = dict(report_views.get("only_failed_gates", {}) or {})
    persisted_summary = dict(failed_gates_view.get("summary", {}) or {})
    persisted_priority = list(failed_gates_view.get("priority", []) or [])
    persisted_severity_priority = list(failed_gates_view.get("severity_priority", []) or [])
    if persisted_summary:
        gate_failure_summary = persisted_summary
    if persisted_priority:
        gate_failure_priority = persisted_priority
    if persisted_severity_priority:
        gate_failure_severity_priority = persisted_severity_priority
    if not gate_failure_severity_priority:
        gate_failure_severity_priority = _build_gate_failure_severity_priority(gate_failure_summary)
    return gate_failure_summary, gate_failure_priority, gate_failure_severity_priority


def _resolve_only_pass_view(
    *,
    summary: dict[str, Any],
    filtered_summary: dict[str, Any],
    pass_results: dict[str, Any],
    pass_name: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    """Resolve pass-scoped symbolic/evidence/context views with summary-first fallbacks."""
    report_views = dict(summary.get("report_views", {}) or {})
    only_pass_map = dict(report_views.get("only_pass", {}) or {})
    summary_pass_symbolic_summary = dict(summary.get("pass_symbolic_summary", {}) or {})
    summary_pass_validation_context = dict(summary.get("pass_validation_context", {}) or {})
    summary_pass_region_evidence_map = dict(summary.get("pass_region_evidence_map", {}) or {})
    normalized_pass_map = _normalized_pass_map(list(summary.get("normalized_pass_results", []) or []))
    symbolic_summary = filtered_summary.get("pass_symbolic_summary", {}).get(pass_name)
    if symbolic_summary is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        symbolic_summary = compact_row.get("symbolic_summary") or summary_pass_symbolic_summary.get(pass_name)
    if symbolic_summary is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        normalized_row = normalized_pass_map.get(pass_name) or compact_row.get("normalized") or compact_row
        if normalized_row:
            symbolic_summary = {
                "pass_name": pass_name,
                "severity": normalized_row.get("severity", "not-requested"),
                "issue_count": normalized_row.get("issue_count", 0),
                "symbolic_requested": normalized_row.get("symbolic_requested", 0),
                "observable_match": normalized_row.get("observable_match", 0),
                "observable_mismatch": normalized_row.get("observable_mismatch", 0),
                "bounded_only": normalized_row.get("bounded_only", 0),
                "without_coverage": normalized_row.get("without_coverage", 0),
                "issues": [],
            }
    pass_evidence = next(
        (row for row in filtered_summary.get("pass_evidence", []) if row.get("pass_name") == pass_name),
        None,
    )
    if pass_evidence is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        pass_evidence = compact_row.get("evidence")
        normalized_row = normalized_pass_map.get(pass_name) or compact_row.get("normalized") or compact_row
        if normalized_row:
            pass_evidence = pass_evidence or {
                "pass_name": pass_name,
                "changed_region_count": normalized_row.get("changed_region_count", 0),
                "changed_bytes": normalized_row.get("changed_bytes", 0),
                "structural_issue_count": normalized_row.get("structural_issue_count", 0),
                "symbolic_binary_mismatched_regions": normalized_row.get("symbolic_binary_mismatched_regions", 0),
            }
    context = filtered_summary.get("pass_validation_context", {}).get(pass_name)
    if context is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        context = compact_row.get("validation_context") or summary_pass_validation_context.get(
            pass_name, pass_results.get(pass_name, {}).get("validation_context")
        )
    if context is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        normalized_row = normalized_pass_map.get(pass_name) or compact_row.get("normalized") or compact_row
        if normalized_row:
            role = normalized_row.get("role", "requested-mode")
            context = {
                "role": role,
                "requested_validation_mode": filtered_summary.get("requested_validation_mode", "off"),
                "effective_validation_mode": filtered_summary.get("validation_mode", "off"),
                "degraded_execution": role == "executed-under-degraded-mode",
                "degradation_triggered_by_pass": role == "degradation-trigger",
            }
    region_evidence = summary_pass_region_evidence_map.get(pass_name)
    if region_evidence is None:
        compact_row = dict(only_pass_map.get(pass_name, {}) or {})
        region_evidence = compact_row.get("region_evidence")
    return symbolic_summary, pass_evidence, context, region_evidence


def _resolve_report_gate_state(
    *,
    summary: dict[str, Any],
    payload: dict[str, Any],
    gate_evaluation: dict[str, Any],
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Resolve persisted gate summaries and filtered gate state for report()."""
    gate_failure_summary = _summarize_gate_failures(gate_evaluation) if gate_evaluation else {}
    gate_failure_priority = list(summary.get("gate_failure_priority", payload.get("gate_failure_priority", [])))
    gate_failure_severity_priority = list(
        summary.get(
            "gate_failure_severity_priority",
            payload.get("gate_failure_severity_priority", []),
        )
    )
    gate_failure_summary, gate_failure_priority, gate_failure_severity_priority = _resolve_failed_gates_view(
        summary=summary,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
    )
    if gate_failure_summary.get("require_pass_severity_failures_by_pass"):
        ordered_failures = sorted(
            gate_failure_summary["require_pass_severity_failures_by_pass"].items(),
            key=lambda item: (
                min(_expected_severity_rank_from_failure(failure) for failure in item[1]),
                -len(item[1]),
                item[0],
            ),
        )
        gate_failure_summary["require_pass_severity_failures_by_pass"] = {
            pass_name: failures for pass_name, failures in ordered_failures
        }
    if not gate_failure_priority:
        gate_failure_priority = [
            {
                "pass_name": pass_name,
                "failure_count": len(failures),
                "strictest_expected_severity": min(
                    (
                        severity
                        for severity in (re.search(r"expected <= ([^)]+)", failure) for failure in failures)
                        if severity
                    ),
                    key=lambda match: _expected_severity_rank_from_failure(f"expected <= {match.group(1)}"),
                ).group(1)
                if failures
                else "unknown",
                "failures": list(failures),
            }
            for pass_name, failures in gate_failure_summary.get("require_pass_severity_failures_by_pass", {}).items()
        ]
    gate_failure_summary, gate_failure_priority, gate_failure_severity_priority, filtered_gate_failed = (
        _filter_failed_gates_view(
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            only_expected_severity=only_expected_severity,
            resolved_only_pass_failure=resolved_only_pass_failure,
        )
    )
    return (
        gate_failure_summary,
        gate_failure_priority,
        gate_failure_severity_priority,
        filtered_gate_failed,
    )


def _resolve_general_symbolic_state(
    *,
    summary: dict[str, Any],
    mutations: list[dict[str, Any]],
    pass_results: dict[str, Any],
) -> dict[str, Any]:
    """Resolve symbolic summary inputs for the general report path."""
    (
        symbolic_requested,
        observable_match,
        observable_mismatch,
        bounded_only,
        observable_not_run,
        by_pass,
        mismatch_rows,
    ) = _summarize_symbolic_view_from_mutations(summary=summary, mutations=mutations)
    summary_normalized_pass_results = list(summary.get("normalized_pass_results", []) or [])
    return {
        "symbolic_requested": symbolic_requested,
        "observable_match": observable_match,
        "observable_mismatch": observable_mismatch,
        "bounded_only": bounded_only,
        "observable_not_run": observable_not_run,
        "by_pass": by_pass,
        "mismatch_rows": mismatch_rows,
        "summary_normalized_pass_results": summary_normalized_pass_results,
        "normalized_pass_map": _normalized_pass_map(summary_normalized_pass_results),
    }


def _resolve_mismatch_severity_rows(
    *,
    summary: dict[str, Any],
    filtered_summary: dict[str, Any],
    filtered_passes: list[str],
    mismatch_degraded_passes: list[dict[str, Any]],
    mismatch_counts_by_pass: dict[str, int],
) -> list[dict[str, Any]]:
    """Resolve per-pass symbolic severity rows for only-mismatches."""
    mismatch_severity_rows = [
        row for row in list(summary.get("symbolic_severity_by_pass", [])) if row.get("pass_name") in filtered_passes
    ]
    if not mismatch_severity_rows and mismatch_degraded_passes:
        mismatch_severity_rows = [
            {
                "pass_name": item.get("pass_name", item.get("mutation", "unknown")),
                "severity": (
                    filtered_summary["pass_symbolic_summary"]
                    .get(item.get("pass_name", item.get("mutation", "unknown")), {})
                    .get("severity", "mismatch")
                ),
                "issue_count": (
                    filtered_summary["pass_symbolic_summary"]
                    .get(item.get("pass_name", item.get("mutation", "unknown")), {})
                    .get("issue_count", 0)
                ),
                "symbolic_requested": (
                    filtered_summary["pass_symbolic_summary"]
                    .get(item.get("pass_name", item.get("mutation", "unknown")), {})
                    .get("symbolic_requested", 0)
                ),
            }
            for item in mismatch_degraded_passes
        ]
    if not mismatch_severity_rows:
        mismatch_severity_rows = [
            {
                "pass_name": pass_name,
                "severity": (filtered_summary["pass_symbolic_summary"].get(pass_name, {}).get("severity", "mismatch")),
                "issue_count": mismatch_counts_by_pass.get(pass_name, 0),
                "symbolic_requested": mismatch_counts_by_pass.get(pass_name, 0),
            }
            for pass_name in filtered_passes
        ]
    return mismatch_severity_rows


