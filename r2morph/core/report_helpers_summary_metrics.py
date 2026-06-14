"""Summary metrics helpers for report generation."""

from __future__ import annotations

from typing import Any


def _summarize_pass_timings(pass_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a compact per-pass timing summary for tooling."""
    rows: list[dict[str, Any]] = []
    for pass_name, pass_result in pass_results.items():
        validation = pass_result.get("validation", {})
        rows.append(
            {
                "pass_name": pass_name,
                "execution_time_seconds": round(float(pass_result.get("execution_time_seconds", 0.0)), 6),
                "mutations": len(pass_result.get("mutations", [])),
                "rolled_back": bool(pass_result.get("rolled_back", False)),
                "validation_issue_count": len(validation.get("issues", [])),
            }
        )
    rows.sort(key=lambda item: (-item["execution_time_seconds"], item["pass_name"]))
    return rows


def _summarize_diff_digest(pass_results: dict[str, Any]) -> dict[str, Any]:
    """Build a compact diff digest across passes."""
    digest: dict[str, Any] = {
        "changed_region_count": 0,
        "changed_bytes": 0,
        "mutation_kinds": [],
        "passes_with_changes": [],
    }
    mutation_kinds: set[str] = set()
    passes_with_changes: list[dict[str, Any]] = []
    for pass_name, pass_result in pass_results.items():
        diff_summary = pass_result.get("diff_summary", {})
        changed_regions = list(diff_summary.get("changed_regions", []))
        changed_bytes = int(diff_summary.get("changed_bytes", 0))
        digest["changed_region_count"] += len(changed_regions)
        digest["changed_bytes"] += changed_bytes
        mutation_kinds.update(diff_summary.get("mutation_kinds", []))
        if changed_regions or changed_bytes:
            passes_with_changes.append(
                {
                    "pass_name": pass_name,
                    "changed_region_count": len(changed_regions),
                    "changed_bytes": changed_bytes,
                }
            )
    passes_with_changes.sort(
        key=lambda item: (-item["changed_bytes"], -item["changed_region_count"], item["pass_name"])
    )
    digest["mutation_kinds"] = sorted(mutation_kinds)
    digest["passes_with_changes"] = passes_with_changes
    return digest
