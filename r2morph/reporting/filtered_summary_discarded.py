"""Discarded-summary population helpers."""

from __future__ import annotations

from typing import Any


def _populate_filtered_summary_discarded_sections(
    *,
    filtered_summary: dict[str, Any],
    summary_discarded_mutation_summary: dict[str, Any],
    summary_discarded_view: dict[str, Any],
    summary_discarded_mutation_priority: list[dict[str, Any]],
) -> None:
    """Populate discarded-mutation sections with summary-first compact/final rows."""
    if summary_discarded_mutation_summary:
        filtered_summary["discarded_mutation_summary"] = summary_discarded_mutation_summary
    if summary_discarded_view:
        if summary_discarded_view.get("final_by_pass"):
            filtered_summary["discarded_mutation_final_by_pass"] = dict(summary_discarded_view.get("final_by_pass", {}))
        if summary_discarded_view.get("final_rows"):
            filtered_summary["discarded_mutation_final_rows"] = list(summary_discarded_view.get("final_rows", []))
        if summary_discarded_view.get("compact_rows"):
            filtered_summary["discarded_mutation_compact_rows"] = list(summary_discarded_view.get("compact_rows", []))
        if summary_discarded_view.get("compact_by_pass"):
            filtered_summary["discarded_mutation_compact_by_pass"] = dict(
                summary_discarded_view.get("compact_by_pass", {})
            )
        if summary_discarded_view.get("compact_by_reason"):
            filtered_summary["discarded_mutation_compact_by_reason"] = dict(
                summary_discarded_view.get("compact_by_reason", {})
            )
        if summary_discarded_view.get("compact_summary"):
            filtered_summary["discarded_mutation_compact_summary"] = dict(
                summary_discarded_view.get("compact_summary", {})
            )
    elif summary_discarded_mutation_priority:
        if "discarded_mutation_final_rows" not in filtered_summary:
            filtered_summary["discarded_mutation_final_rows"] = [
                {
                    "pass_name": row.get("pass_name"),
                    "reasons": list(row.get("reasons", {}).keys()) if isinstance(row.get("reasons"), dict) else [],
                }
                for row in summary_discarded_mutation_priority
                if row.get("pass_name")
            ]
        if "discarded_mutation_compact_rows" not in filtered_summary:
            filtered_summary["discarded_mutation_compact_rows"] = list(summary_discarded_mutation_priority)
        if "discarded_mutation_compact_by_reason" not in filtered_summary:
            by_reason: dict[str, int] = {}
            for row in summary_discarded_mutation_priority:
                reasons = row.get("reasons", {})
                if isinstance(reasons, dict):
                    for reason, count in reasons.items():
                        by_reason[reason] = by_reason.get(reason, 0) + count
            filtered_summary["discarded_mutation_compact_by_reason"] = by_reason
