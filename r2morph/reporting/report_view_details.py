"""Detail assembly helpers for report views."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_context import ReportViewInputs, ReportViews
from r2morph.reporting.report_view_gate_detail import build_gate_detail
from r2morph.reporting.report_view_mismatch_detail import build_mismatch_detail
from r2morph.reporting.report_view_projections import _build_category_views, _summarize_rows
from r2morph.reporting.report_view_validation_detail import build_validation_adjustments_detail


def _build_mismatch_detail(
    observable_mismatch_priority: list[dict[str, Any]],
    mismatch_rows: list[dict[str, Any]],
    mismatch_by_pass: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build the only_mismatches detail section."""
    return build_mismatch_detail(observable_mismatch_priority, mismatch_rows, mismatch_by_pass)


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
    inputs: ReportViewInputs,
    sections: dict[str, Any],
) -> ReportViews:
    """Assemble the final ReportViews from pre-built components."""
    return ReportViews(
        general_passes=sections["general_pass_rows"],
        general_pass_rows=sections["general_pass_rows"],
        general_summary=sections["general_summary_payload"],
        general_summary_rows=sections["general_summary_rows"],
        general_renderer_state=sections["general_renderer_state"],
        general_triage_rows=[dict(row) for row in sections["triage_priority"]],
        general_filter_views=sections["filter_buckets"],
        general_symbolic=sections["general_symbolic"],
        general_gates=sections["general_gates"],
        general_degradation=sections["general_degradation"],
        general_discards=sections["general_discards"],
        passes=sections["filter_buckets"],
        triage_priority=sections["triage_priority"],
        only_pass=sections["only_pass"],
        pass_filter_views={
            "only_risky_passes": sections["filter_buckets"].get("risky", []),
            "only_structural_risk": sections["filter_buckets"].get("structural_risk", []),
            "only_symbolic_risk": sections["filter_buckets"].get("symbolic_risk", []),
            "only_clean_passes": sections["filter_buckets"].get("clean", []),
            "only_covered_passes": sections["filter_buckets"].get("covered", []),
            "only_uncovered_passes": sections["filter_buckets"].get("uncovered", []),
        },
        mismatch_priority=[dict(row) for row in inputs.observable_mismatch_priority],
        mismatch_map={str(pass_name): dict(row) for pass_name, row in inputs.observable_mismatch_map.items()},
        mismatch_view=sections["mismatch_rows"],
        only_mismatches=_build_mismatch_detail(
            inputs.observable_mismatch_priority,
            sections["mismatch_rows"],
            sections["mismatch_by_pass"],
        ),
        failed_gates=[dict(row) for row in inputs.gate_failure_priority],
        only_failed_gates=build_gate_detail(
            inputs.gate_failure_priority,
            inputs.gate_failure_summary,
            inputs.gate_failure_severity_priority,
            sections,
        ),
        validation_adjustments=_build_validation_adjustments_detail(sections["degraded_rows"]),
        discarded_view=_build_discarded_detail(
            inputs.discarded_mutation_priority,
            inputs.discarded_mutation_summary,
        ),
    )
