"""Pass-evidence aggregation helpers for reporting."""

from __future__ import annotations

from typing import Any

from r2morph.core.report_helpers_region_evidence import (
    _build_pass_region_evidence_map as _build_pass_region_evidence_map_summary,
)


def _summarize_pass_evidence(pass_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Aggregate per-pass evidence summaries for tooling."""
    rows = []
    for pass_name, pass_result in pass_results.items():
        evidence_summary = pass_result.get("evidence_summary", {})
        rows.append(
            {
                "pass_name": pass_name,
                "changed_region_count": evidence_summary.get("changed_region_count", 0),
                "structural_issue_count": evidence_summary.get("structural_issue_count", 0),
                "symbolic_binary_regions_checked": evidence_summary.get(
                    "symbolic_binary_regions_checked",
                    0,
                ),
                "symbolic_binary_mismatched_regions": evidence_summary.get(
                    "symbolic_binary_mismatched_regions",
                    0,
                ),
                "rolled_back": evidence_summary.get("rolled_back", False),
                "status": evidence_summary.get("status", "unknown"),
            }
        )
    rows.sort(
        key=lambda item: (
            -item["symbolic_binary_mismatched_regions"],
            -item["structural_issue_count"],
            -item["changed_region_count"],
            item["pass_name"],
        )
    )
    return rows


def _build_pass_region_evidence_map(
    pass_results: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Persist compact symbolic region evidence by pass for report consumers."""
    return _build_pass_region_evidence_map_summary(pass_results)
