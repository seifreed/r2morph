"""Pass-evidence aggregation helpers for reporting."""

from __future__ import annotations

from typing import Any


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
    region_map: dict[str, list[dict[str, Any]]] = {}
    for pass_name, pass_result in pass_results.items():
        evidence = dict(pass_result.get("evidence_summary", {}) or {})
        symbolic_regions = list(evidence.get("symbolic_regions", []) or [])
        if not symbolic_regions:
            continue
        region_map[pass_name] = [
            {
                "start_address": row.get("start_address"),
                "end_address": row.get("end_address"),
                "equivalent": bool(row.get("equivalent", False)),
                "mismatch_count": int(row.get("mismatch_count", len(row.get("mismatches", [])))),
                "mismatches": list(row.get("mismatches", [])),
                "step_strategy": row.get("step_strategy"),
                "region_exit_equivalent": (
                    row.get("original_region_exit_address") == row.get("mutated_region_exit_address")
                    and row.get("original_region_exit_address") is not None
                ),
                "original_region_exit_address": row.get("original_region_exit_address"),
                "mutated_region_exit_address": row.get("mutated_region_exit_address"),
                "original_trace_length": int(row.get("original_trace_length", 0)),
                "mutated_trace_length": int(row.get("mutated_trace_length", 0)),
                "original_region_exit_steps": int(row.get("original_region_exit_steps", 0)),
                "mutated_region_exit_steps": int(row.get("mutated_region_exit_steps", 0)),
            }
            for row in symbolic_regions
        ]
    return region_map

