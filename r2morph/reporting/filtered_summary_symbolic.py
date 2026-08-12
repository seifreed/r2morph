"""Symbolic-analysis section helpers for filtered report payloads.

Leaf detail-builders for the symbolic-issue / coverage / severity sections of a
filtered summary, extracted from the report flow -- no logic
changes. Called only by the pass-section orchestrator; never call back into it.
"""

from dataclasses import dataclass
from typing import Any

from r2morph.core.report_helpers_symbolic_summary import classify_symbolic_severity
from r2morph.reporting.report_evidence_sorting import _sort_pass_evidence
from r2morph.reporting.report_helpers import _visible_rows_from_map


@dataclass(frozen=True, slots=True)
class SymbolicPopulation:
    filtered_summary: dict[str, Any]
    summary: dict[str, Any]
    pass_results: dict[str, Any]
    by_pass: dict[str, dict[str, int]]
    degraded_passes: list[dict[str, Any]]
    only_degraded: bool
    summary_sources: dict[str, Any]


def _symbolic_issue_passes_from_by_pass(by_pass: dict[str, dict[str, int]]) -> list[dict[str, Any]]:
    """Build severity-sorted symbolic issue-pass rows from raw by_pass counters."""
    return [
        {
            "pass_name": pass_name,
            "severity": classify_symbolic_severity(pass_stats["observable_mismatch"], pass_stats["without_coverage"]),
            "observable_mismatch": pass_stats["observable_mismatch"],
            "without_coverage": pass_stats["without_coverage"],
            "bounded_only": pass_stats["bounded_only"],
        }
        for pass_name, pass_stats in sorted(
            (
                (name, stats)
                for name, stats in by_pass.items()
                if stats["observable_mismatch"] > 0 or stats["without_coverage"] > 0 or stats["bounded_only"] > 0
            ),
            key=lambda item: (
                -item[1]["observable_mismatch"],
                -item[1]["without_coverage"],
                -item[1]["bounded_only"],
                item[0],
            ),
        )
    ]


def _symbolic_coverage_from_by_pass(by_pass: dict[str, dict[str, int]]) -> list[dict[str, Any]]:
    """Build request-sorted symbolic coverage rows from raw by_pass counters."""
    return [
        {"pass_name": pass_name, **pass_stats}
        for pass_name, pass_stats in sorted(
            ((name, stats) for name, stats in by_pass.items() if stats["symbolic_requested"] > 0),
            key=lambda item: (
                -item[1]["symbolic_requested"],
                -item[1]["observable_match"],
                -item[1]["observable_mismatch"],
                item[0],
            ),
        )
    ]


def _populate_symbolic_issue_passes(state: SymbolicPopulation) -> None:
    """Populate pass_evidence and symbolic_issue_passes sections."""
    filtered_summary = state.filtered_summary
    summary = state.summary
    pass_results = state.pass_results
    by_pass = state.by_pass
    summary_symbolic_issue_map = state.summary_sources["symbolic_issue_map"]
    summary_pass_evidence_compact = state.summary_sources["pass_evidence_compact"]
    summary_general_symbolic = state.summary_sources["general_symbolic"]
    pass_evidence_priority_rows = list(summary.get("pass_evidence_priority", []))
    if pass_evidence_priority_rows:
        filtered_summary["pass_evidence"] = [
            dict(row) for row in pass_evidence_priority_rows if row.get("pass_name") in filtered_summary["passes"]
        ]
    elif summary_pass_evidence_compact:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                dict(row)
                for row in summary_pass_evidence_compact
                if not visible_passes or row.get("pass_name") in visible_passes
            ]
        )
    else:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                row
                for row in list(summary.get("pass_evidence", []))
                if row.get("pass_name") in filtered_summary["passes"]
            ]
        )

    if not filtered_summary["symbolic_issue_passes"] and summary_general_symbolic.get("triage_rows"):
        filtered_summary["symbolic_issue_passes"] = [
            dict(row) for row in list(summary_general_symbolic.get("triage_rows", []))
        ]
    if not filtered_summary["symbolic_issue_passes"]:
        filtered_summary["symbolic_issue_passes"] = _visible_rows_from_map(
            summary_symbolic_issue_map, set(filtered_summary["passes"])
        )
    if not filtered_summary["symbolic_issue_passes"]:
        filtered_summary["symbolic_issue_passes"] = [
            issue
            for pass_name in filtered_summary["passes"]
            for issue in pass_results.get(pass_name, {}).get("symbolic_summary", {}).get("issues", [])
        ]
    if not filtered_summary["symbolic_issue_passes"]:
        filtered_summary["symbolic_issue_passes"] = _symbolic_issue_passes_from_by_pass(by_pass)


def _populate_symbolic_coverage_and_severity(state: SymbolicPopulation) -> None:
    """Populate symbolic_coverage_by_pass and symbolic_severity_by_pass sections."""
    filtered_summary = state.filtered_summary
    by_pass = state.by_pass
    degraded_passes = state.degraded_passes
    only_degraded = state.only_degraded
    pass_results = state.pass_results
    summary_symbolic_coverage_map = state.summary_sources["symbolic_coverage_map"]
    summary_symbolic_severity_map = state.summary_sources["symbolic_severity_map"]
    if not filtered_summary["symbolic_coverage_by_pass"]:
        filtered_summary["symbolic_coverage_by_pass"] = _visible_rows_from_map(
            summary_symbolic_coverage_map, set(filtered_summary["passes"])
        )
    if not filtered_summary["symbolic_coverage_by_pass"]:
        filtered_summary["symbolic_coverage_by_pass"] = [
            pass_results.get(pass_name, {}).get("symbolic_summary", {})
            for pass_name in filtered_summary["passes"]
            if pass_results.get(pass_name, {}).get("symbolic_summary", {}).get("symbolic_requested", 0) > 0
        ]
    if not filtered_summary["symbolic_coverage_by_pass"]:
        filtered_summary["symbolic_coverage_by_pass"] = _symbolic_coverage_from_by_pass(by_pass)

    if not filtered_summary["symbolic_severity_by_pass"]:
        filtered_summary["symbolic_severity_by_pass"] = _visible_rows_from_map(
            summary_symbolic_severity_map, set(filtered_summary["passes"])
        )
    if not filtered_summary["symbolic_severity_by_pass"]:
        filtered_summary["symbolic_severity_by_pass"] = [
            {
                "pass_name": pass_name,
                "severity": summary_row.get("severity", "not-requested"),
                "issue_count": summary_row.get("issue_count", 0),
                "symbolic_requested": summary_row.get("symbolic_requested", 0),
            }
            for pass_name, summary_row in sorted(
                filtered_summary["pass_symbolic_summary"].items(),
                key=lambda item: item[0],
            )
        ]
    if only_degraded and degraded_passes and not filtered_summary["symbolic_severity_by_pass"]:
        filtered_summary["symbolic_severity_by_pass"] = [
            {
                "pass_name": pass_name,
                "severity": filtered_summary["pass_symbolic_summary"]
                .get(pass_name, {})
                .get("severity", "not-requested"),
                "issue_count": filtered_summary["pass_symbolic_summary"].get(pass_name, {}).get("issue_count", 0),
                "symbolic_requested": filtered_summary["pass_symbolic_summary"]
                .get(pass_name, {})
                .get("symbolic_requested", 0),
            }
            for pass_name in [item.get("pass_name", item.get("mutation", "unknown")) for item in degraded_passes]
        ]


def _populate_filtered_summary_symbolic_sections(state: SymbolicPopulation) -> None:
    """Populate symbolic report sections with summary-first fallbacks."""
    filtered_summary = state.filtered_summary
    summary = state.summary
    pass_results = state.pass_results
    by_pass = state.by_pass
    degraded_passes = state.degraded_passes
    only_degraded = state.only_degraded
    summary_symbolic_issue_map = state.summary_sources["symbolic_issue_map"]
    summary_symbolic_coverage_map = state.summary_sources["symbolic_coverage_map"]
    summary_symbolic_severity_map = state.summary_sources["symbolic_severity_map"]
    summary_pass_symbolic_summary = state.summary_sources["pass_symbolic_summary"]
    filtered_summary["symbolic_issue_passes"] = list(summary.get("symbolic_issue_passes", []))
    filtered_summary["symbolic_coverage_by_pass"] = list(summary.get("symbolic_coverage_by_pass", []))
    filtered_summary["symbolic_severity_by_pass"] = list(summary.get("symbolic_severity_by_pass", []))

    if not filtered_summary["symbolic_issue_passes"]:
        filtered_summary["symbolic_issue_passes"] = _visible_rows_from_map(
            summary_symbolic_issue_map, set(filtered_summary["passes"])
        )
    if not filtered_summary["symbolic_issue_passes"]:
        filtered_summary["symbolic_issue_passes"] = [
            issue
            for pass_name in filtered_summary["passes"]
            for issue in pass_results.get(pass_name, {}).get("symbolic_summary", {}).get("issues", [])
        ]
    if not filtered_summary["symbolic_issue_passes"]:
        filtered_summary["symbolic_issue_passes"] = _symbolic_issue_passes_from_by_pass(by_pass)

    if not filtered_summary["symbolic_coverage_by_pass"]:
        filtered_summary["symbolic_coverage_by_pass"] = _visible_rows_from_map(
            summary_symbolic_coverage_map, set(filtered_summary["passes"])
        )
    if not filtered_summary["symbolic_coverage_by_pass"]:
        filtered_summary["symbolic_coverage_by_pass"] = [
            pass_results.get(pass_name, {}).get("symbolic_summary", {})
            for pass_name in filtered_summary["passes"]
            if pass_results.get(pass_name, {}).get("symbolic_summary", {}).get("symbolic_requested", 0) > 0
        ]
    if not filtered_summary["symbolic_coverage_by_pass"]:
        filtered_summary["symbolic_coverage_by_pass"] = _symbolic_coverage_from_by_pass(by_pass)

    if not filtered_summary["symbolic_severity_by_pass"]:
        filtered_summary["symbolic_severity_by_pass"] = _visible_rows_from_map(
            summary_symbolic_severity_map, set(filtered_summary["passes"])
        )
    if not filtered_summary["symbolic_severity_by_pass"]:
        filtered_summary["symbolic_severity_by_pass"] = [
            {
                "pass_name": pass_name,
                "severity": summary_row.get("severity", "not-requested"),
                "issue_count": summary_row.get("issue_count", 0),
                "symbolic_requested": summary_row.get("symbolic_requested", 0),
            }
            for pass_name, summary_row in sorted(
                summary_pass_symbolic_summary.items(),
                key=lambda item: item[0],
            )
        ]
    if only_degraded and degraded_passes and not filtered_summary["symbolic_severity_by_pass"]:
        filtered_summary["symbolic_severity_by_pass"] = [
            {
                "pass_name": pass_name,
                "severity": filtered_summary["pass_symbolic_summary"]
                .get(pass_name, {})
                .get("severity", "not-requested"),
                "issue_count": filtered_summary["pass_symbolic_summary"].get(pass_name, {}).get("issue_count", 0),
                "symbolic_requested": filtered_summary["pass_symbolic_summary"]
                .get(pass_name, {})
                .get("symbolic_requested", 0),
            }
            for pass_name in [item.get("pass_name", item.get("mutation", "unknown")) for item in degraded_passes]
        ]
