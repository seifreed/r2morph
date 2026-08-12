"""Discarded-summary population helpers."""

from __future__ import annotations

from typing import Any


def _apply_discarded_view(filtered_summary: dict[str, Any], discarded_view: dict[str, Any]) -> None:
    projections = (
        ("final_by_pass", "discarded_mutation_final_by_pass", dict),
        ("final_rows", "discarded_mutation_final_rows", list),
        ("compact_rows", "discarded_mutation_compact_rows", list),
        ("compact_by_pass", "discarded_mutation_compact_by_pass", dict),
        ("compact_by_reason", "discarded_mutation_compact_by_reason", dict),
        ("compact_summary", "discarded_mutation_compact_summary", dict),
    )
    for source_key, target_key, converter in projections:
        if discarded_view.get(source_key):
            filtered_summary[target_key] = converter(discarded_view[source_key])


def _apply_discarded_priority(
    filtered_summary: dict[str, Any],
    discarded_priority: list[dict[str, Any]],
) -> None:
    if "discarded_mutation_final_rows" not in filtered_summary:
        filtered_summary["discarded_mutation_final_rows"] = [
            {
                "pass_name": row.get("pass_name"),
                "reasons": list(row.get("reasons", {}).keys()) if isinstance(row.get("reasons"), dict) else [],
            }
            for row in discarded_priority
            if row.get("pass_name")
        ]
    if "discarded_mutation_compact_rows" not in filtered_summary:
        filtered_summary["discarded_mutation_compact_rows"] = list(discarded_priority)
    if "discarded_mutation_compact_by_reason" not in filtered_summary:
        by_reason: dict[str, int] = {}
        for row in discarded_priority:
            reasons = row.get("reasons", {})
            if isinstance(reasons, dict):
                for reason, count in reasons.items():
                    by_reason[reason] = by_reason.get(reason, 0) + count
        filtered_summary["discarded_mutation_compact_by_reason"] = by_reason


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
        _apply_discarded_view(filtered_summary, summary_discarded_view)
    elif summary_discarded_mutation_priority:
        _apply_discarded_priority(filtered_summary, summary_discarded_mutation_priority)
