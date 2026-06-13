"""Shared row-projection helpers for report view construction.

Leaf-level, stateless helpers that project and summarize report rows. They
eliminate the per-category row-shape duplication that the view builders would
otherwise repeat. Split out of report_view_builder.py to keep that module
within the file-size budget (CLAUDE.md §14); the view builders import these
primitives, so this module never depends back on report_view_builder.
"""

from typing import Any


def _project_rows(rows: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
    """Project rows to a subset of fields with type normalization."""
    result = []
    for row in rows:
        projected: dict[str, Any] = {}
        for f in fields:
            val = row.get(f)
            if isinstance(val, bool):
                projected[f] = val
            elif isinstance(val, int):
                projected[f] = val
            elif isinstance(val, dict):
                projected[f] = dict(val)
            elif isinstance(val, list):
                projected[f] = list(val)
            elif val is None:
                projected[f] = row.get(f, "")
            else:
                projected[f] = str(val) if val else ""
        result.append(projected)
    return result


def _project_by_pass(rows: list[dict[str, Any]], fields: list[str]) -> dict[str, dict[str, Any]]:
    """Project rows keyed by pass_name."""
    projected = _project_rows([r for r in rows if r.get("pass_name")], fields)
    return {str(r.get("pass_name", "")): r for r in projected}


def _build_category_views(
    rows: list[dict[str, Any]],
    compact_fields: list[str],
    final_fields: list[str] | None = None,
) -> dict[str, Any]:
    """Build compact/final rows and by-pass indexes for a category.

    Returns dict with: compact_by_pass, compact_rows, final_rows, final_by_pass.
    """
    if final_fields is None:
        final_fields = compact_fields
    return {
        "compact_by_pass": _project_by_pass(rows, compact_fields),
        "compact_rows": _project_rows(rows, compact_fields),
        "final_rows": _project_rows(rows, final_fields),
        "final_by_pass": _project_by_pass(rows, final_fields),
    }


def _summarize_rows(rows: list[dict[str, Any]], count_fields: list[str]) -> dict[str, Any]:
    """Build a compact summary from rows with pass list and count aggregations."""
    summary: dict[str, Any] = {"pass_count": len(rows)}
    for f in count_fields:
        summary[f] = sum(int(row.get(f, 0)) for row in rows)
    summary["passes"] = [str(row.get("pass_name")) for row in rows if row.get("pass_name")]
    return summary


def _build_lookup_maps(
    *,
    normalized_pass_results: list[dict[str, Any]],
    pass_triage_rows: list[dict[str, Any]],
    symbolic_severity_by_pass: list[dict[str, Any]],
    discarded_mutation_summary: dict[str, Any],
) -> dict[str, Any]:
    """Build normalized_pass_map, triage_priority, symbolic_severity_map, discarded_by_pass."""
    normalized_pass_map = {
        str(row.get("pass_name")): dict(row) for row in normalized_pass_results if row.get("pass_name")
    }
    triage_priority = [
        dict(row)
        for row in sorted(
            (row for row in pass_triage_rows if row.get("pass_name")),
            key=lambda row: (
                int(row.get("severity_order", 99)),
                -int(row.get("structural_issue_count", 0)),
                -int(row.get("symbolic_binary_mismatched_regions", 0)),
                str(row.get("pass_name", "")),
            ),
        )
    ]
    symbolic_severity_map = {
        str(row.get("pass_name")): dict(row) for row in symbolic_severity_by_pass if row.get("pass_name")
    }
    discarded_by_pass = {
        str(row.get("pass_name")): dict(row)
        for row in list(discarded_mutation_summary.get("by_pass", []) or [])
        if row.get("pass_name")
    }
    return {
        "normalized_pass_map": normalized_pass_map,
        "triage_priority": triage_priority,
        "symbolic_severity_map": symbolic_severity_map,
        "discarded_by_pass": discarded_by_pass,
    }
