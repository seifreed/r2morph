"""Filtered-summary payload helpers for the `--only-mismatches` path."""

from typing import Any

from r2morph.core.report_helpers_indexing import _index_rows_by_pass_name
from r2morph.reporting.report_context import FilterFlags, ReportFlowContext, SeverityFilter


def _resolve_final_rows(
    final_rows: list[dict[str, Any]],
    compact_rows: list[dict[str, Any]],
    final_by_pass: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not final_rows and compact_rows and final_by_pass:
        return [dict(final_by_pass[pass_name]) for pass_name in sorted(final_by_pass)]
    if not final_rows:
        return [
            {
                "pass_name": str(row.get("pass_name", "")),
                "mismatch_count": int(row.get("mismatch_count", 0)),
                "severity": row.get("severity", "mismatch"),
                "role": row.get("role", "requested-mode"),
                "symbolic_confidence": row.get("symbolic_confidence", "unknown"),
                "degraded_execution": bool(row.get("degraded_execution", False)),
                "region_count": int(row.get("region_count", 0)),
                "region_mismatch_count": int(row.get("region_mismatch_count", 0)),
                "region_exit_match_count": int(row.get("region_exit_match_count", 0)),
                "compact_region": dict(row.get("compact_region", {})),
            }
            for row in compact_rows
        ]
    compact_row_by_pass = _index_rows_by_pass_name(compact_rows)
    final_rows = [dict(row) for row in final_rows]
    for row in final_rows:
        compact_region = compact_row_by_pass.get(str(row.get("pass_name", "")), {}).get("compact_region")
        if "compact_region" not in row and compact_region:
            row["compact_region"] = dict(compact_region)
    return final_rows


def _build_only_mismatches_filtered_summary(
    ctx: ReportFlowContext,
    mismatch_state: dict[str, Any],
    mismatch_view: dict[str, Any],
) -> dict[str, Any]:
    """Build the filtered_summary payload for `report --only-mismatches`."""
    filtered_mutations = mismatch_state["filtered_mutations"]
    filtered_passes = mismatch_state["filtered_passes"]
    mismatch_counts_by_pass = mismatch_state["mismatch_counts_by_pass"]
    mismatch_observables_by_pass = mismatch_state["mismatch_observables_by_pass"]
    final_rows = list(mismatch_view.get("final_rows", []) or [])
    compact_rows = list(mismatch_view.get("compact_rows", []) or [])
    compact_by_pass = dict(mismatch_view.get("compact_by_pass", {}) or {})
    compact_summary = dict(mismatch_view.get("compact_summary", {}) or {})
    final_by_pass = dict(mismatch_view.get("final_by_pass", {}) or {})
    final_rows = _resolve_final_rows(final_rows, compact_rows, final_by_pass)
    if not compact_by_pass and compact_rows:
        compact_by_pass = _index_rows_by_pass_name(compact_rows)
    if not compact_summary:
        compact_summary = {
            "pass_count": len(compact_rows) or len(filtered_passes),
            "mismatch_count": sum(mismatch_counts_by_pass.values()),
            "degraded_pass_count": len([row for row in compact_rows if row.get("degraded_execution")]),
            "region_count": sum(int(row.get("region_count", 0)) for row in compact_rows),
            "region_mismatch_count": sum(int(row.get("region_mismatch_count", 0)) for row in compact_rows),
            "region_exit_match_count": sum(int(row.get("region_exit_match_count", 0)) for row in compact_rows),
            "passes": list(filtered_passes),
        }
    filtered_summary: dict[str, Any] = {
        "mutations": len(filtered_mutations),
        "passes": filtered_passes,
        "symbolic_requested": sum(
            1 for mutation in filtered_mutations if mutation.get("metadata", {}).get("symbolic_requested")
        ),
        "observable_match": 0,
        "observable_mismatch": len(filtered_mutations),
        "bounded_only": 0,
        "without_symbolic_coverage": 0,
        "symbolic_statuses": (
            {"bounded-step-observable-mismatch": len(filtered_mutations)} if filtered_mutations else {}
        ),
        "pass_capabilities": {
            pass_name: ctx.data.pass_support.get(pass_name, {}).get("validator_capabilities", {})
            for pass_name in filtered_passes
            if ctx.data.pass_support.get(pass_name)
        },
        "symbolic_severity_by_pass": mismatch_state["mismatch_severity_rows"],
        "mismatch_counts_by_pass": mismatch_counts_by_pass,
        "mismatch_observables_by_pass": mismatch_observables_by_pass,
        "observable_mismatch_priority": [
            dict(row)
            for row in mismatch_state["persisted_mismatch_priority"]
            if row.get("pass_name") in filtered_passes
        ]
        or [
            {
                "pass_name": pass_name,
                "mismatch_count": mismatch_counts_by_pass.get(pass_name, 0),
                "observables": mismatch_observables_by_pass.get(pass_name, []),
            }
            for pass_name in filtered_passes
        ],
        "pass_validation_context": mismatch_state["mismatch_pass_context"],
        "pass_region_evidence_map": {
            pass_name: list(ctx.data.filtered_summary.get("pass_region_evidence_map", {}).get(pass_name, []))
            for pass_name in filtered_passes
            if ctx.data.filtered_summary.get("pass_region_evidence_map", {}).get(pass_name)
        },
        "mismatch_compact_rows": compact_rows,
        "mismatch_compact_by_pass": compact_by_pass,
        "mismatch_compact_summary": compact_summary,
        "mismatch_final_rows": final_rows,
        "mismatch_final_by_pass": final_by_pass,
        "requested_validation_mode": ctx.validation.requested_validation_mode or "",
        "validation_mode": ctx.validation.effective_validation_mode or "",
        "degraded_validation": ctx.validation.degraded_validation,
        "degraded_passes": mismatch_state["mismatch_degraded_passes"] or ctx.validation.degraded_passes,
        "degradation_roles": ctx.validation.degradation_roles,
        "failed_gates": ctx.gates.failed_gates,
    }
    if ctx.gates.gate_evaluation:
        filtered_summary["gate_evaluation"] = ctx.gates.gate_evaluation
        filtered_summary["gate_failures"] = ctx.gates.gate_failure_summary
        filtered_summary["gate_failure_priority"] = ctx.gates.gate_failure_priority
        filtered_summary["gate_failure_severity_priority"] = ctx.gates.gate_failure_severity_priority
    if ctx.severity.min_severity is not None:
        filtered_summary["min_severity"] = ctx.severity.min_severity
    if ctx.filters.only_expected_severity is not None:
        filtered_summary["only_expected_severity"] = ctx.filters.only_expected_severity
    if ctx.severity.resolved_only_pass_failure is not None:
        filtered_summary["only_pass_failure"] = ctx.severity.resolved_only_pass_failure
    if ctx.validation.validation_policy is not None:
        filtered_summary["validation_policy"] = ctx.validation.validation_policy
    return filtered_summary


def _build_only_mismatches_payload(
    ctx: ReportFlowContext,
    mismatch_state: dict[str, Any],
) -> dict[str, Any]:
    """Build the filtered payload for report --only-mismatches."""
    mismatch_view = dict((dict(ctx.data.summary.get("report_views", {}) or {})).get("only_mismatches", {}) or {})
    filtered_payload = dict(ctx.data.payload)
    filtered_payload["mutations"] = mismatch_state["filtered_mutations"]
    filtered_payload["filtered_summary"] = _build_only_mismatches_filtered_summary(ctx, mismatch_state, mismatch_view)
    return filtered_payload


def _build_report_filters(
    filters: FilterFlags,
    severity: SeverityFilter,
) -> dict[str, object]:
    """Build a stable report_filters payload."""
    values: dict[str, object | None] = {
        "only_mismatches": filters.only_mismatches,
        "only_pass": severity.resolved_only_pass,
        "only_status": filters.only_status,
        "only_degraded": filters.only_degraded,
        "only_failed_gates": filters.only_failed_gates,
        "only_risky_passes": filters.only_risky_passes,
        "only_uncovered_passes": filters.only_uncovered_passes,
        "only_covered_passes": filters.only_covered_passes,
        "only_clean_passes": filters.only_clean_passes,
        "only_structural_risk": filters.only_structural_risk,
        "only_symbolic_risk": filters.only_symbolic_risk,
        "min_severity": severity.min_severity,
        "only_expected_severity": filters.only_expected_severity,
        "only_pass_failure": severity.resolved_only_pass_failure,
    }
    return {name: value for name, value in values.items() if value not in (None, False, "")}
