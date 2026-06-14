"""Pure helpers for resolving mismatch views from persisted report state."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_summary_lookup import _summary_first


def _resolve_mismatch_view_from_summary(
    summary: dict[str, Any],
) -> tuple[dict[str, int], dict[str, list[str]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Build mismatch counts/observables/priority from persisted summary state."""
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
        return counts_by_pass, observables_by_pass, mismatch_priority, mismatch_view

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
            str(row.get("pass_name")): list(row.get("observables", [])) for row in mismatch_view if row.get("pass_name")
        }
    return counts_by_pass, observables_by_pass, mismatch_priority, mismatch_view


def _merge_mismatch_observables_from_mutations(
    counts_by_pass: dict[str, int],
    observables_by_pass: dict[str, list[str]],
    mutations: list[dict[str, Any]],
) -> tuple[dict[str, int], dict[str, list[str]]]:
    """Merge live mutation rows into the persisted mismatch view."""
    for mutation in mutations:
        pass_name = str(mutation.get("pass_name", "unknown"))
        counts_by_pass[pass_name] = counts_by_pass.get(pass_name, 0) + 1
        mismatch_observables = mutation.get("metadata", {}).get("symbolic_observable_mismatches", [])
        if mismatch_observables:
            merged = set(observables_by_pass.get(pass_name, []))
            merged.update(mismatch_observables)
            observables_by_pass[pass_name] = sorted(merged)
    return counts_by_pass, observables_by_pass
