"""Report mismatch state resolution helpers."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_state import (
    resolve_mismatch_view as _resolve_mismatch_view_impl,
)


def resolve_only_mismatches_state(
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
    mismatch_counts_by_pass, mismatch_observables_by_pass, persisted_mismatch_priority = _resolve_mismatch_view_impl(
        summary=summary, mutations=filtered_mutations
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
