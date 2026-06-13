"""Risk-filtering helpers for filtered summary population."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_helpers import _sort_pass_evidence


def _apply_risk_filters(
    *,
    filtered_summary: dict[str, Any],
    selected_risk_pass_names: set[str],
    only_risky_filters: bool,
) -> None:
    """Apply risk-based filtering and final symbolic summary fallbacks."""
    if only_risky_filters:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [row for row in filtered_summary["pass_evidence"] if row.get("pass_name") in selected_risk_pass_names]
        )
        filtered_summary["symbolic_issue_passes"] = [
            row for row in filtered_summary["symbolic_issue_passes"] if row.get("pass_name") in selected_risk_pass_names
        ]
        filtered_summary["symbolic_coverage_by_pass"] = [
            row
            for row in filtered_summary["symbolic_coverage_by_pass"]
            if row.get("pass_name") in selected_risk_pass_names
        ]
        filtered_summary["symbolic_severity_by_pass"] = [
            row
            for row in filtered_summary["symbolic_severity_by_pass"]
            if row.get("pass_name") in selected_risk_pass_names
        ]
        filtered_summary["pass_capabilities"] = {
            pass_name: capabilities
            for pass_name, capabilities in filtered_summary["pass_capabilities"].items()
            if pass_name in selected_risk_pass_names
        }
        filtered_summary["pass_validation_context"] = {
            pass_name: context
            for pass_name, context in filtered_summary["pass_validation_context"].items()
            if pass_name in selected_risk_pass_names
        }
        filtered_summary["pass_symbolic_summary"] = {
            pass_name: summary_row
            for pass_name, summary_row in filtered_summary["pass_symbolic_summary"].items()
            if pass_name in selected_risk_pass_names
        }

    if not filtered_summary["pass_symbolic_summary"]:
        for row in filtered_summary["symbolic_coverage_by_pass"]:
            pass_name = row.get("pass_name")
            if not pass_name:
                continue
            filtered_summary["pass_symbolic_summary"][pass_name] = {
                **row,
                "issues": [
                    issue for issue in filtered_summary["symbolic_issue_passes"] if issue.get("pass_name") == pass_name
                ],
            }
    if not filtered_summary["pass_symbolic_summary"] and filtered_summary["normalized_pass_results"]:
        for row in filtered_summary["normalized_pass_results"]:
            pass_name = row.get("pass_name")
            if not pass_name:
                continue
            filtered_summary["pass_symbolic_summary"][str(pass_name)] = {
                "pass_name": str(pass_name),
                "severity": row.get("severity", "not-requested"),
                "issue_count": row.get("issue_count", 0),
                "symbolic_requested": row.get("symbolic_requested", 0),
                "observable_match": row.get("observable_match", 0),
                "observable_mismatch": row.get("observable_mismatch", 0),
                "bounded_only": row.get("bounded_only", 0),
                "without_coverage": row.get("without_coverage", 0),
                "issues": [],
            }
    if not filtered_summary["pass_symbolic_summary"] and filtered_summary["pass_evidence"]:
        for row in filtered_summary["pass_evidence"]:
            pass_name = row.get("pass_name")
            if not pass_name:
                continue
            filtered_summary["pass_symbolic_summary"][str(pass_name)] = {
                "pass_name": str(pass_name),
                "severity": row.get("severity", "not-requested"),
                "issue_count": row.get("issue_count", 0),
                "symbolic_requested": row.get("symbolic_requested", 0),
                "observable_match": row.get("observable_match", 0),
                "observable_mismatch": row.get("observable_mismatch", 0),
                "bounded_only": row.get("bounded_only", 0),
                "without_coverage": row.get("without_coverage", 0),
                "issues": [],
            }
    if not filtered_summary["symbolic_severity_by_pass"] and filtered_summary["pass_symbolic_summary"]:
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
