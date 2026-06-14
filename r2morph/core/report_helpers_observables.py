"""Observable mismatch report helpers extracted from core.report_helpers."""

from __future__ import annotations

from typing import Any

from r2morph.core.report_helpers_indexing import _index_rows_by_pass_name


def _summarize_observable_mismatches_by_pass(
    mutations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Aggregate observable symbolic mismatches by pass for report triage."""
    counts: dict[str, dict[str, Any]] = {}
    for mutation in mutations:
        metadata = mutation.get("metadata", {})
        if not metadata.get("symbolic_observable_check_performed"):
            continue
        if metadata.get("symbolic_observable_equivalent", False):
            continue
        pass_name = mutation.get("pass_name", "unknown")
        row = counts.setdefault(
            pass_name,
            {
                "pass_name": pass_name,
                "mismatch_count": 0,
                "observables": set(),
            },
        )
        row["mismatch_count"] += 1
        row["observables"].update(metadata.get("symbolic_observable_mismatches", []))

    rows = [
        {
            "pass_name": row["pass_name"],
            "mismatch_count": row["mismatch_count"],
            "observables": sorted(row["observables"]),
        }
        for row in counts.values()
    ]
    rows.sort(key=lambda item: (-item["mismatch_count"], item["pass_name"]))
    return rows


def _build_observable_mismatch_map(
    rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Build a machine-readable lookup for observable mismatches by pass."""
    return _index_rows_by_pass_name(rows)


def _build_observable_mismatch_priority(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build a stable priority view for observable mismatches."""
    priority = [dict(row) for row in rows]
    priority.sort(
        key=lambda item: (
            -int(item.get("mismatch_count", 0)),
            -len(item.get("observables", [])),
            str(item.get("pass_name", "")),
        )
    )
    return priority
