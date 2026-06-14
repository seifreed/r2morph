"""Triage and result population helpers for filtered summaries."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.filtered_summary_discarded import _populate_filtered_summary_discarded_sections
from r2morph.reporting.report_helpers import _summary_first, _visible_rows, _visible_rows_from_map


def _populate_triage_and_results(
    *,
    filtered_summary: dict[str, Any],
    summary: dict[str, Any],
    summary_pass_triage_map: dict[str, Any],
    summary_normalized_pass_results: list[dict[str, Any]],
    summary_pass_capability_summary_map: dict[str, Any],
    summary_validation_role_map: dict[str, Any],
    summary_report_views: dict[str, Any],
    summary_general_pass_rows: list[dict[str, Any]],
    summary_general_passes: list[dict[str, Any]],
    summary_discarded_mutation_summary: dict[str, Any],
    summary_discarded_view: dict[str, Any],
    summary_discarded_mutation_priority: list[dict[str, Any]],
    summary_general_discards: dict[str, Any],
) -> None:
    """Populate triage rows, normalized results, capability summary, and validation role rows."""
    pass_triage_rows = list(
        _summary_first(summary, "pass_triage_rows", summary_report_views.get("triage_priority", [])) or []
    )
    if pass_triage_rows:
        filtered_summary["pass_triage_rows"] = _visible_rows(
            pass_triage_rows,
            set(filtered_summary["passes"]),
        )
    elif summary_pass_triage_map:
        filtered_summary["pass_triage_rows"] = _visible_rows_from_map(
            summary_pass_triage_map, set(filtered_summary["passes"])
        )
    if summary_normalized_pass_results:
        filtered_summary["normalized_pass_results"] = _visible_rows(
            summary_normalized_pass_results,
            set(filtered_summary["passes"]),
        )
    elif summary_general_pass_rows:
        filtered_summary["normalized_pass_results"] = _visible_rows(
            summary_general_pass_rows,
            set(filtered_summary["passes"]),
        )
    elif summary_general_passes:
        filtered_summary["normalized_pass_results"] = _visible_rows(
            summary_general_passes,
            set(filtered_summary["passes"]),
        )

    capability_rows = list(summary.get("pass_capability_summary", []))
    if capability_rows:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_capability_summary"] = [
            dict(row) for row in capability_rows if not visible_passes or row.get("pass_name") in visible_passes
        ]
    elif summary_pass_capability_summary_map:
        filtered_summary["pass_capability_summary"] = _visible_rows_from_map(
            summary_pass_capability_summary_map, set(filtered_summary["passes"])
        )
    elif summary_general_pass_rows:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_capability_summary"] = [
            {
                "pass_name": str(row.get("pass_name")),
                "runtime_recommended": bool(row.get("runtime_recommended", False)),
                "symbolic_recommended": bool(row.get("symbolic_recommended", False)),
                "symbolic_confidence": row.get("symbolic_confidence", "unknown"),
            }
            for row in summary_general_pass_rows
            if row.get("pass_name") and (not visible_passes or row.get("pass_name") in visible_passes)
        ]

    validation_role_rows = list(summary.get("validation_role_rows", []))
    if validation_role_rows:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["validation_role_rows"] = [
            dict(row) for row in validation_role_rows if not visible_passes or row.get("pass_name") in visible_passes
        ]
    elif summary_validation_role_map:
        filtered_summary["validation_role_rows"] = _visible_rows_from_map(
            summary_validation_role_map, set(filtered_summary["passes"])
        )

    _populate_filtered_summary_discarded_sections(
        filtered_summary=filtered_summary,
        summary_discarded_mutation_summary=summary_discarded_mutation_summary,
        summary_discarded_view=summary_discarded_view,
        summary_discarded_mutation_priority=summary_discarded_mutation_priority,
    )
    if "discarded_mutation_compact_summary" not in filtered_summary and summary_general_discards.get("summary"):
        filtered_summary["discarded_mutation_compact_summary"] = dict(summary_general_discards.get("summary", {}))
    if "discarded_mutation_compact_rows" not in filtered_summary and summary_general_discards.get("rows"):
        filtered_summary["discarded_mutation_compact_rows"] = list(summary_general_discards.get("rows", []))
