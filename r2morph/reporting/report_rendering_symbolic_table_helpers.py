"""Pure row builders for symbolic report tables."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_helpers import _sort_pass_evidence


def build_symbolic_coverage_rows(
    *,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    by_pass: dict[str, dict[str, int]],
) -> list[dict[str, Any]]:
    """Build the coverage rows using summary-first fallbacks."""
    coverage_rows = list(summary.get("symbolic_coverage_by_pass", []))
    if not coverage_rows:
        coverage_rows = [
            pass_result.get("symbolic_summary", {})
            for pass_result in pass_results.values()
            if pass_result.get("symbolic_summary", {}).get("symbolic_requested", 0) > 0
        ]
    if not coverage_rows:
        coverage_rows = [
            {"pass_name": pass_name, **pass_stats}
            for pass_name, pass_stats in by_pass.items()
            if pass_stats["symbolic_requested"] > 0
        ]
    return coverage_rows


def build_symbolic_issue_rows(
    *,
    summary: dict[str, Any],
    by_pass: dict[str, dict[str, int]],
) -> list[dict[str, Any]]:
    """Build the pass issue rows using summary-first fallbacks."""
    issue_rows = list(summary.get("symbolic_issue_passes", []))
    if issue_rows:
        return issue_rows

    pass_evidence_rows = list(summary.get("pass_evidence", []))
    issue_rows = [
        {
            "pass_name": row.get("pass_name", "unknown"),
            "severity": (
                "mismatch"
                if int(row.get("symbolic_binary_mismatched_regions", 0)) > 0
                else "without-coverage" if int(row.get("without_coverage", 0)) > 0 else "bounded-only"
            ),
            "observable_mismatch": int(row.get("symbolic_binary_mismatched_regions", 0)),
            "without_coverage": int(row.get("without_coverage", 0)),
            "bounded_only": int(row.get("bounded_only", 0)),
        }
        for row in pass_evidence_rows
        if row.get("pass_name")
        and (
            int(row.get("symbolic_binary_mismatched_regions", 0)) > 0
            or int(row.get("without_coverage", 0)) > 0
            or int(row.get("bounded_only", 0)) > 0
        )
    ]
    issue_rows.sort(
        key=lambda item: (
            -item["observable_mismatch"],
            -item["without_coverage"],
            -item["bounded_only"],
            item["pass_name"],
        )
    )
    if issue_rows:
        return issue_rows

    issue_rows = [
        {
            "pass_name": pass_name,
            "severity": (
                "mismatch"
                if pass_stats["observable_mismatch"] > 0
                else "without-coverage" if pass_stats["without_coverage"] > 0 else "bounded-only"
            ),
            "observable_mismatch": pass_stats["observable_mismatch"],
            "without_coverage": pass_stats["without_coverage"],
            "bounded_only": pass_stats["bounded_only"],
        }
        for pass_name, pass_stats in by_pass.items()
        if pass_stats["symbolic_requested"] > 0
    ]
    issue_rows.sort(
        key=lambda item: (
            -item["observable_mismatch"],
            -item["without_coverage"],
            -item["bounded_only"],
            item["pass_name"],
        )
    )
    return issue_rows


def build_symbolic_severity_rows(
    *,
    summary: dict[str, Any],
    by_pass: dict[str, dict[str, int]],
    coverage_rows: list[dict[str, Any]],
    issue_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build the severity priority rows using summary-first fallbacks."""
    severity_rows = list(summary.get("symbolic_severity_by_pass", []))
    if severity_rows:
        return severity_rows

    issue_severity_map = {row.get("pass_name"): row.get("severity") for row in issue_rows if row.get("pass_name")}
    severity_rows = [
        {
            "pass_name": row.get("pass_name", "unknown"),
            "severity": issue_severity_map.get(row.get("pass_name")) or row.get("severity", "not-requested"),
            "issue_count": row.get("issue_count", 0),
            "symbolic_requested": row.get("symbolic_requested", 0),
        }
        for row in coverage_rows
    ]
    if severity_rows:
        return severity_rows

    if issue_rows:
        severity_rows = [
            {
                "pass_name": row.get("pass_name", "unknown"),
                "severity": row.get("severity", "not-requested"),
                "issue_count": row.get("issue_count", 0),
                "symbolic_requested": row.get("symbolic_requested", 0),
            }
            for row in issue_rows
        ]
        if severity_rows:
            return severity_rows

    severity_rows = [
        {
            "pass_name": pass_name,
            "severity": (
                "mismatch"
                if pass_stats["observable_mismatch"] > 0
                else "without-coverage" if pass_stats["without_coverage"] > 0 else "bounded-only"
            ),
            "issue_count": (
                pass_stats["observable_mismatch"] + pass_stats["without_coverage"] + pass_stats["bounded_only"]
            ),
            "symbolic_requested": pass_stats["symbolic_requested"],
        }
        for pass_name, pass_stats in by_pass.items()
        if pass_stats["symbolic_requested"] > 0
    ]
    severity_rows.sort(key=lambda item: item["pass_name"])
    if severity_rows:
        return severity_rows

    pass_evidence_rows = list(summary.get("pass_evidence", []))
    severity_rows = [
        {
            "pass_name": row.get("pass_name", "unknown"),
            "severity": (
                "mismatch"
                if int(row.get("symbolic_binary_mismatched_regions", 0)) > 0
                else "without-coverage" if int(row.get("without_coverage", 0)) > 0 else "bounded-only"
            ),
            "issue_count": (
                int(row.get("issue_count", 0))
                or int(row.get("symbolic_binary_mismatched_regions", 0))
                + int(row.get("without_coverage", 0))
                + int(row.get("bounded_only", 0))
            ),
            "symbolic_requested": int(row.get("symbolic_requested", 0)),
        }
        for row in pass_evidence_rows
        if row.get("pass_name")
        and (
            int(row.get("symbolic_binary_mismatched_regions", 0)) > 0
            or int(row.get("without_coverage", 0)) > 0
            or int(row.get("bounded_only", 0)) > 0
        )
    ]
    severity_rows.sort(key=lambda item: item["pass_name"])
    return severity_rows


def build_pass_evidence_rows(summary: dict[str, Any], pass_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Build pass evidence rows using summary-first fallbacks and stable sorting."""
    pass_evidence_rows = list(summary.get("pass_evidence_compact", []))
    pass_evidence_priority_rows = list(summary.get("pass_evidence_priority", []))
    if pass_evidence_priority_rows:
        pass_evidence_rows = [dict(row) for row in pass_evidence_priority_rows if row.get("pass_name")]
    elif not pass_evidence_rows:
        pass_evidence_rows = _sort_pass_evidence(
            [row for row in list(summary.get("pass_evidence", [])) if row.get("pass_name")]
        )
    if not pass_evidence_rows:
        pass_evidence_rows = _sort_pass_evidence(
            [
                dict(pass_results.get(pass_name, {}).get("evidence_summary", {}))
                for pass_name in sorted(pass_results)
                if pass_results.get(pass_name, {}).get("evidence_summary")
            ]
        )
    return pass_evidence_rows
