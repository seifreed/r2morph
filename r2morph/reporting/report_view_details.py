"""Detail assembly helpers for report views."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_context import ReportViews
from r2morph.reporting.report_view_gate_detail import build_gate_detail
from r2morph.reporting.report_view_projections import _build_category_views, _summarize_rows
from r2morph.reporting.report_view_validation_detail import build_validation_adjustments_detail


def _build_mismatch_detail(
    observable_mismatch_priority: list[dict[str, Any]],
    mismatch_rows: list[dict[str, Any]],
    mismatch_by_pass: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build the only_mismatches detail section."""
    return {
        "priority": [dict(row) for row in observable_mismatch_priority],
        "by_pass": mismatch_by_pass,
        **_build_category_views(
            mismatch_rows,
            compact_fields=[
                "pass_name",
                "mismatch_count",
                "severity",
                "role",
                "symbolic_confidence",
                "degraded_execution",
                "region_count",
                "region_mismatch_count",
                "region_exit_match_count",
                "compact_region",
            ],
        ),
        "rows": mismatch_rows,
        "compact_summary": {
            **_summarize_rows(
                mismatch_rows,
                ["mismatch_count", "region_count", "region_mismatch_count", "region_exit_match_count"],
            ),
            "degraded_pass_count": sum(1 for row in mismatch_rows if row.get("degraded_execution")),
        },
        "summary": {
            **_summarize_rows(
                mismatch_rows,
                ["mismatch_count", "region_count", "region_mismatch_count", "region_exit_match_count"],
            ),
            "degraded_pass_count": sum(1 for row in mismatch_rows if row.get("degraded_execution")),
            "trigger_pass_count": sum(1 for row in mismatch_rows if row.get("degradation_triggered_by_pass")),
        },
    }


def _build_gate_detail(
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_summary: dict[str, Any] | None,
    gate_failure_severity_priority: list[dict[str, Any]],
    failed_gates_rows: list[dict[str, Any]],
    failed_gates_by_pass: dict[str, dict[str, Any]],
    failed_gates_expected_severity: dict[str, Any],
) -> dict[str, Any]:
    """Build the only_failed_gates detail section."""
    return build_gate_detail(
        gate_failure_priority,
        gate_failure_summary,
        gate_failure_severity_priority,
        failed_gates_rows,
        failed_gates_by_pass,
        failed_gates_expected_severity,
    )


def _build_validation_adjustments_detail(degraded_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the validation_adjustments detail section."""
    return build_validation_adjustments_detail(degraded_rows)


def _build_discarded_detail(
    discarded_mutation_priority: list[dict[str, Any]],
    discarded_mutation_summary: dict[str, Any],
) -> dict[str, Any]:
    """Build the discarded_view detail section."""
    return {
        "priority": [dict(row) for row in discarded_mutation_priority],
        "rows": [dict(row) for row in discarded_mutation_priority],
        **_build_category_views(
            discarded_mutation_priority,
            compact_fields=["pass_name", "discarded_count", "impact_severity", "reason_count"],
            final_fields=["pass_name", "discarded_count", "impact_severity", "reason_count", "reasons"],
        ),
        "by_reason": dict(discarded_mutation_summary.get("by_reason", {})),
        "compact_by_reason": {
            str(reason): int(count)
            for reason, count in discarded_mutation_summary.get("by_reason", {}).items()
            if count
        },
        "by_pass": [dict(row) for row in discarded_mutation_summary.get("by_pass", [])],
        "by_impact": dict(discarded_mutation_summary.get("by_impact", {})),
        "summary": {
            "count": len(discarded_mutation_priority),
            "passes": [str(row.get("pass_name")) for row in discarded_mutation_priority if row.get("pass_name")],
            "reasons": sorted(
                str(reason) for reason, count in discarded_mutation_summary.get("by_reason", {}).items() if count
            ),
            "impacts": {
                str(level): len(rows) for level, rows in discarded_mutation_summary.get("by_impact", {}).items()
            },
        },
        "compact_summary": {
            "count": len(discarded_mutation_priority),
            **_summarize_rows(discarded_mutation_priority, []),
            "reason_count": len(
                [reason for reason, count in discarded_mutation_summary.get("by_reason", {}).items() if count]
            ),
            "impact_counts": {
                str(level): len(rows) for level, rows in discarded_mutation_summary.get("by_impact", {}).items()
            },
        },
    }


def _assemble_report_views(
    *,
    general_pass_rows: list[dict[str, Any]],
    general_summary_payload: dict[str, Any],
    general_summary_rows: list[dict[str, Any]],
    general_renderer_state: dict[str, Any],
    triage_priority: list[dict[str, Any]],
    filter_buckets: dict[str, list[str]] | None,
    general_symbolic: dict[str, Any],
    general_gates: dict[str, Any],
    general_degradation: dict[str, Any],
    general_discards: dict[str, Any],
    only_pass: dict[str, dict[str, Any]],
    observable_mismatch_priority: list[dict[str, Any]],
    observable_mismatch_map: dict[str, dict[str, Any]],
    mismatch_rows: list[dict[str, Any]],
    mismatch_by_pass: dict[str, dict[str, Any]],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_summary: dict[str, Any] | None,
    gate_failure_severity_priority: list[dict[str, Any]],
    failed_gates_rows: list[dict[str, Any]],
    failed_gates_by_pass: dict[str, dict[str, Any]],
    failed_gates_expected_severity: dict[str, Any],
    degraded_rows: list[dict[str, Any]],
    discarded_mutation_priority: list[dict[str, Any]],
    discarded_mutation_summary: dict[str, Any],
) -> ReportViews:
    """Assemble the final ReportViews from pre-built components."""
    return ReportViews(
        general_passes=general_pass_rows,
        general_pass_rows=general_pass_rows,
        general_summary=general_summary_payload,
        general_summary_rows=general_summary_rows,
        general_renderer_state=general_renderer_state,
        general_triage_rows=[dict(row) for row in triage_priority],
        general_filter_views=filter_buckets or {},
        general_symbolic=general_symbolic,
        general_gates=general_gates,
        general_degradation=general_degradation,
        general_discards=general_discards,
        passes=filter_buckets or {},
        triage_priority=triage_priority,
        only_pass=only_pass,
        pass_filter_views={
            "only_risky_passes": (filter_buckets or {}).get("risky", []),
            "only_structural_risk": (filter_buckets or {}).get("structural_risk", []),
            "only_symbolic_risk": (filter_buckets or {}).get("symbolic_risk", []),
            "only_clean_passes": (filter_buckets or {}).get("clean", []),
            "only_covered_passes": (filter_buckets or {}).get("covered", []),
            "only_uncovered_passes": (filter_buckets or {}).get("uncovered", []),
        },
        mismatch_priority=[dict(row) for row in observable_mismatch_priority],
        mismatch_map={str(pass_name): dict(row) for pass_name, row in observable_mismatch_map.items()},
        mismatch_view=mismatch_rows,
        only_mismatches=_build_mismatch_detail(observable_mismatch_priority, mismatch_rows, mismatch_by_pass),
        failed_gates=[dict(row) for row in gate_failure_priority],
        only_failed_gates=_build_gate_detail(
            gate_failure_priority,
            gate_failure_summary,
            gate_failure_severity_priority,
            failed_gates_rows,
            failed_gates_by_pass,
            failed_gates_expected_severity,
        ),
        validation_adjustments=_build_validation_adjustments_detail(degraded_rows),
        discarded_view=_build_discarded_detail(discarded_mutation_priority, discarded_mutation_summary),
    )
