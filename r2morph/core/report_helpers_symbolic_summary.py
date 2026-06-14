"""Symbolic summary aggregation helpers for reporting."""

from __future__ import annotations

from typing import Any

from r2morph.core.constants import SEVERITY_ORDER, UNKNOWN_SEVERITY_RANK


def _summarize_symbolic_issue_passes(
    mutations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Aggregate symbolic issue counts by pass for machine-readable reports."""
    by_pass: dict[str, dict[str, int]] = {}
    for mutation in mutations:
        metadata = mutation.get("metadata", {})
        if not metadata.get("symbolic_requested"):
            continue
        pass_name = mutation.get("pass_name", "unknown")
        stats = by_pass.setdefault(
            pass_name,
            {
                "observable_mismatch": 0,
                "without_coverage": 0,
                "bounded_only": 0,
            },
        )
        if metadata.get("symbolic_observable_check_performed"):
            if not metadata.get("symbolic_observable_equivalent", False):
                stats["observable_mismatch"] += 1
        elif metadata.get("symbolic_status") in {
            "bounded-step-passed",
            "bounded-step-known-equivalence",
            "bounded-step-observables-match",
            "bounded-step-observable-mismatch",
        }:
            stats["bounded_only"] += 1
        else:
            stats["without_coverage"] += 1

    issue_rows: list[dict[str, Any]] = []
    for pass_name, stats in by_pass.items():
        if stats["observable_mismatch"] == 0 and stats["without_coverage"] == 0 and stats["bounded_only"] == 0:
            continue
        severity = (
            "mismatch"
            if stats["observable_mismatch"] > 0
            else "without-coverage" if stats["without_coverage"] > 0 else "bounded-only"
        )
        issue_rows.append(
            {
                "pass_name": pass_name,
                "severity": severity,
                "observable_mismatch": stats["observable_mismatch"],
                "without_coverage": stats["without_coverage"],
                "bounded_only": stats["bounded_only"],
            }
        )
    issue_rows.sort(
        key=lambda item: (
            -int(item["observable_mismatch"]),
            -int(item["without_coverage"]),
            -int(item["bounded_only"]),
            item["pass_name"],
        )
    )
    return issue_rows


def _summarize_symbolic_coverage_by_pass(
    mutations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Aggregate symbolic coverage outcomes by pass for machine-readable reports."""
    by_pass: dict[str, dict[str, int]] = {}

    for mutation in mutations:
        metadata = mutation.get("metadata", {})
        if not metadata.get("symbolic_requested"):
            continue
        pass_name = mutation.get("pass_name", "unknown")
        stats = by_pass.setdefault(
            pass_name,
            {
                "symbolic_requested": 0,
                "observable_match": 0,
                "observable_mismatch": 0,
                "bounded_only": 0,
                "without_coverage": 0,
            },
        )
        stats["symbolic_requested"] += 1
        if metadata.get("symbolic_observable_check_performed"):
            if metadata.get("symbolic_observable_equivalent", False):
                stats["observable_match"] += 1
            else:
                stats["observable_mismatch"] += 1
        elif metadata.get("symbolic_status") in {
            "bounded-step-passed",
            "bounded-step-known-equivalence",
            "bounded-step-observables-match",
            "bounded-step-observable-mismatch",
        }:
            stats["bounded_only"] += 1
        else:
            stats["without_coverage"] += 1

    rows: list[dict[str, Any]] = []
    for pass_name, stats in by_pass.items():
        rows.append({"pass_name": pass_name, **stats})
    rows.sort(
        key=lambda item: (
            -int(item["symbolic_requested"]),
            -int(item["observable_match"]),
            -int(item["observable_mismatch"]),
            item["pass_name"],
        )
    )
    return rows


def _summarize_symbolic_statuses(
    mutations: list[dict[str, Any]],
) -> tuple[dict[str, int], list[dict[str, Any]], dict[str, dict[str, int]]]:
    """Build global and per-pass symbolic status summaries."""
    global_counts: dict[str, int] = {}
    by_pass: dict[str, dict[str, int]] = {}
    for mutation in mutations:
        status = mutation.get("metadata", {}).get("symbolic_status")
        if not status:
            continue
        status = str(status)
        global_counts[status] = global_counts.get(status, 0) + 1
        pass_name = str(mutation.get("pass_name", "unknown"))
        pass_counts = by_pass.setdefault(pass_name, {})
        pass_counts[status] = pass_counts.get(status, 0) + 1
    rows: list[dict[str, Any]] = [
        {
            "pass_name": pass_name,
            "statuses": dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))),
        }
        for pass_name, counts in by_pass.items()
    ]
    rows.sort(
        key=lambda item: (
            -sum(dict(item["statuses"]).values()),
            item["pass_name"],
        )
    )
    return (
        dict(sorted(global_counts.items(), key=lambda item: (-item[1], item[0]))),
        rows,
        {str(row["pass_name"]): dict(row["statuses"]) for row in rows},
    )


def _build_symbolic_summary_for_pass(
    pass_name: str,
    mutations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a symbolic coverage/issues summary for one pass."""
    pass_mutations = [mutation for mutation in mutations if mutation.get("pass_name", "unknown") == pass_name]
    coverage_rows = _summarize_symbolic_coverage_by_pass(pass_mutations)
    issue_rows = _summarize_symbolic_issue_passes(pass_mutations)
    coverage = (
        coverage_rows[0]
        if coverage_rows
        else {
            "pass_name": pass_name,
            "symbolic_requested": 0,
            "observable_match": 0,
            "observable_mismatch": 0,
            "bounded_only": 0,
            "without_coverage": 0,
        }
    )
    severity = (
        issue_rows[0]["severity"] if issue_rows else "clean" if coverage["symbolic_requested"] > 0 else "not-requested"
    )
    return {
        **coverage,
        "severity": severity,
        "issue_count": len(issue_rows),
        "issues": issue_rows,
    }


def _summarize_symbolic_severity_by_pass(
    pass_results: dict[str, Any],
) -> list[dict[str, Any]]:
    """Aggregate symbolic severity by pass from per-pass summaries."""
    rows = []
    for pass_name, pass_result in pass_results.items():
        symbolic_summary = pass_result.get("symbolic_summary", {})
        rows.append(
            {
                "pass_name": pass_name,
                "severity": symbolic_summary.get("severity", "not-requested"),
                "issue_count": symbolic_summary.get("issue_count", 0),
                "symbolic_requested": symbolic_summary.get("symbolic_requested", 0),
            }
        )
    rows.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], UNKNOWN_SEVERITY_RANK),
            -item["issue_count"],
            -item["symbolic_requested"],
            item["pass_name"],
        )
    )
    return rows


def _summarize_symbolic_overview(
    symbolic_coverage_by_pass: list[dict[str, Any]],
    symbolic_status_counts: dict[str, int],
) -> dict[str, Any]:
    """Build a compact global symbolic overview."""
    overview: dict[str, Any] = {
        "symbolic_requested": 0,
        "observable_match": 0,
        "observable_mismatch": 0,
        "bounded_only": 0,
        "without_coverage": 0,
        "statuses": dict(symbolic_status_counts),
    }
    for row in symbolic_coverage_by_pass:
        overview["symbolic_requested"] += int(row.get("symbolic_requested", 0))
        overview["observable_match"] += int(row.get("observable_match", 0))
        overview["observable_mismatch"] += int(row.get("observable_mismatch", 0))
        overview["bounded_only"] += int(row.get("bounded_only", 0))
        overview["without_coverage"] += int(row.get("without_coverage", 0))
    return overview

