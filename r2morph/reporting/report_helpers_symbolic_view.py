"""Symbolic-view report helpers extracted from report_helpers."""

from __future__ import annotations

from typing import Any


def _summarize_symbolic_view_from_mutations(
    *,
    summary: dict[str, Any],
    mutations: list[dict[str, Any]],
) -> tuple[int, int, int, int, int, dict[str, dict[str, int]], list[tuple[str, int | None, int | None, list[str]]]]:
    """Resolve symbolic overview counters using summary first, mutation scan as fallback."""
    symbolic_overview = dict(summary.get("symbolic_overview", {}) or {})
    symbolic_requested = int(symbolic_overview.get("symbolic_requested", 0))
    observable_match = int(symbolic_overview.get("observable_match", 0))
    observable_mismatch = int(symbolic_overview.get("observable_mismatch", 0))
    observable_not_run = int(symbolic_overview.get("without_coverage", 0))
    bounded_only = int(symbolic_overview.get("bounded_only", 0))
    by_pass: dict[str, dict[str, int]] = {}
    mismatch_rows: list[tuple[str, int | None, int | None, list[str]]] = []

    for mutation in mutations:
        pass_name = mutation.get("pass_name", "unknown")
        pass_stats = by_pass.setdefault(
            pass_name,
            {
                "symbolic_requested": 0,
                "observable_match": 0,
                "observable_mismatch": 0,
                "bounded_only": 0,
                "without_coverage": 0,
            },
        )
        metadata = mutation.get("metadata", {})
        if not metadata.get("symbolic_requested"):
            continue
        if not symbolic_overview:
            symbolic_requested += 1
        pass_stats["symbolic_requested"] += 1
        if metadata.get("symbolic_observable_check_performed"):
            if metadata.get("symbolic_observable_equivalent"):
                if not symbolic_overview:
                    observable_match += 1
                pass_stats["observable_match"] += 1
            else:
                if not symbolic_overview:
                    observable_mismatch += 1
                pass_stats["observable_mismatch"] += 1
                mismatch_rows.append(
                    (
                        pass_name,
                        mutation.get("start_address"),
                        mutation.get("end_address"),
                        list(metadata.get("symbolic_observable_mismatches", [])),
                    )
                )
        elif metadata.get("symbolic_status") in {
            "bounded-step-passed",
            "bounded-step-known-equivalence",
            "bounded-step-observables-match",
            "bounded-step-observable-mismatch",
        }:
            if not symbolic_overview:
                bounded_only += 1
            pass_stats["bounded_only"] += 1
        else:
            if not symbolic_overview:
                observable_not_run += 1
            pass_stats["without_coverage"] += 1

    return (
        symbolic_requested,
        observable_match,
        observable_mismatch,
        bounded_only,
        observable_not_run,
        by_pass,
        mismatch_rows,
    )
