"""Symbolic report table rendering helpers."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from r2morph.reporting.report_helpers import _sort_pass_evidence


def _render_match_table(
    *,
    console: Console,
    observable_match: int,
    observable_mismatch: int,
    bounded_only: int,
    observable_not_run: int,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    by_pass: dict[str, dict[str, int]],
) -> list[dict[str, Any]]:
    """Render the symbolic match/coverage overview and return resolved coverage_rows."""
    console.print(
        "[bold]Symbolic Mutation Summary[/bold]: "
        f"{observable_match} observable match, "
        f"{observable_mismatch} observable mismatch, "
        f"{bounded_only} bounded-step only, "
        f"{observable_not_run} without symbolic coverage"
    )
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
    for row in coverage_rows:
        console.print(
            f"  [cyan]{row['pass_name']}[/cyan]: "
            f"{row['observable_match']} match, "
            f"{row['observable_mismatch']} mismatch, "
            f"{row['bounded_only']} bounded-only, "
            f"{row['without_coverage']} without coverage"
        )
    return coverage_rows


def _render_mismatch_table(
    *,
    console: Console,
    summary: dict[str, Any],
    by_pass: dict[str, dict[str, int]],
    coverage_rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Render severity priority and issue rows; return (severity_rows, issue_rows)."""
    issue_rows = list(summary.get("symbolic_issue_passes", []))
    severity_rows = list(summary.get("symbolic_severity_by_pass", []))
    if not severity_rows:
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
    if not severity_rows and issue_rows:
        severity_rows = [
            {
                "pass_name": row.get("pass_name", "unknown"),
                "severity": row.get("severity", "not-requested"),
                "issue_count": row.get("issue_count", 0),
                "symbolic_requested": row.get("symbolic_requested", 0),
            }
            for row in issue_rows
        ]
    if not severity_rows:
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
    if not severity_rows:
        pass_evidence_rows = list(summary.get("pass_evidence", []))
        severity_rows = [
            {
                "pass_name": row.get("pass_name", "unknown"),
                "severity": (
                    "mismatch"
                    if int(row.get("symbolic_binary_mismatched_regions", 0)) > 0
                    else "without-coverage"
                    if int(row.get("without_coverage", 0)) > 0
                    else "bounded-only"
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
    if severity_rows:
        console.print("[bold]Severity Priority[/bold]:")
        for row in severity_rows:
            console.print(
                f"  [cyan]{row['pass_name']}[/cyan]: "
                f"severity={row['severity']}, "
                f"issue_count={row.get('issue_count', 0)}, "
                f"symbolic_requested={row.get('symbolic_requested', 0)}"
            )
    if not issue_rows:
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
        console.print("[bold]Passes With Symbolic Issues[/bold]:")
        for row in issue_rows:
            severity = row["severity"]
            if severity_rows:
                severity = next(
                    (
                        item.get("severity", severity)
                        for item in severity_rows
                        if item.get("pass_name") == row["pass_name"]
                    ),
                    severity,
                )
            console.print(
                f"  [yellow]{row['pass_name']}[/yellow]: "
                f"severity={severity}, "
                f"mismatch={row['observable_mismatch']}, "
                f"without_coverage={row['without_coverage']}, "
                f"bounded_only={row['bounded_only']}"
            )
    return severity_rows, issue_rows


def _render_coverage_table(
    *,
    console: Console,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    mismatch_rows: list[tuple[str, int | None, int | None, list[str]]],
) -> None:
    """Render triage, evidence, capabilities, discarded mutations, and mismatch details."""
    triage_rows = list(summary.get("pass_triage_rows", []))
    if triage_rows:
        console.print("[bold]Pass Triage[/bold]:")
        for row in triage_rows:
            console.print(
                f"  [cyan]{row['pass_name']}[/cyan]: "
                f"severity={row.get('severity', 'unknown')}, "
                f"structural_issues={row.get('structural_issue_count', 0)}, "
                f"symbolic_mismatch={row.get('symbolic_binary_mismatched_regions', 0)}, "
                f"role={row.get('role', 'unknown')}, "
                f"symbolic_confidence={row.get('symbolic_confidence', 'unknown')}"
            )
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
    if pass_evidence_rows:
        console.print("[bold]Pass Evidence[/bold]:")
        for row in pass_evidence_rows:
            console.print(
                f"  [cyan]{row['pass_name']}[/cyan]: "
                f"changed_regions={row.get('changed_region_count', 0)}, "
                f"structural_issues={row.get('structural_issue_count', 0)}, "
                f"symbolic_checked={row.get('symbolic_binary_regions_checked', 0)}, "
                f"symbolic_mismatch={row.get('symbolic_binary_mismatched_regions', 0)}"
            )
    capability_rows = list(summary.get("pass_capability_summary", []))
    if capability_rows:
        console.print("[bold]Pass Capabilities[/bold]:")
        for row in capability_rows:
            console.print(
                f"  [cyan]{row['pass_name']}[/cyan]: "
                f"runtime_recommended={str(row.get('runtime_recommended', False)).lower()}, "
                f"symbolic_recommended={str(row.get('symbolic_recommended', False)).lower()}, "
                f"symbolic_confidence={row.get('symbolic_confidence', 'unknown')}"
            )
    discarded_priority = list(summary.get("discarded_mutation_priority", []))
    discarded_summary = dict(summary.get("discarded_mutation_summary", {}) or {})
    if discarded_priority or discarded_summary.get("by_pass"):
        console.print("[bold]Discarded Mutations[/bold]:")
        for row in discarded_priority or discarded_summary["by_pass"]:
            reasons = ",".join(f"{reason}:{count}" for reason, count in dict(row.get("reasons", {})).items())
            console.print(
                f"  [cyan]{row['pass_name']}[/cyan]: "
                f"discarded={row.get('discarded_count', 0)}" + (f", reasons={reasons}" if reasons else "")
            )
    if mismatch_rows:
        console.print("[bold]Symbolic Mismatches[/bold]:")
        for pass_name, start, end, observables in mismatch_rows:
            if start is None or end is None:
                location = "unknown"
            elif start == end:
                location = f"0x{start:x}"
            else:
                location = f"0x{start:x}-0x{end:x}"
            details = ", ".join(observables) if observables else "unknown"
            console.print(f"  [red]{pass_name}[/red] @ {location}: {details}")
