"""Overview summary aggregation helpers for report generation."""

from __future__ import annotations

from typing import Any


def summarize_degradation_roles(pass_results: dict[str, Any]) -> dict[str, int]:
    """Aggregate degradation role counts across pass validation contexts."""
    counts: dict[str, int] = {}
    for pass_result in pass_results.values():
        role = pass_result.get("validation_context", {}).get("role")
        if not role:
            continue
        counts[role] = counts.get(role, 0) + 1
    return counts


def summarize_pass_timings(pass_results: dict[str, Any]) -> list[dict[str, Any]]:
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
    rows.sort(key=lambda item: (-float(item["execution_time_seconds"]), item["pass_name"]))
    return rows

