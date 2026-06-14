"""Detailed reporting summary aggregation helpers."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.gate_evaluator import ROLLBACK_SEVERITY_ORDER


def summarize_diff_digest(pass_results: dict[str, Any]) -> dict[str, Any]:
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
        digest["changed_region_count"] = int(digest["changed_region_count"]) + len(changed_regions)
        digest["changed_bytes"] = int(digest["changed_bytes"]) + changed_bytes
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
        key=lambda item: (
            -item["changed_bytes"],
            -item["changed_region_count"],
            item["pass_name"],
        )
    )
    digest["mutation_kinds"] = sorted(mutation_kinds)
    digest["passes_with_changes"] = passes_with_changes
    return digest


def summarize_discarded_mutations(discarded_mutations: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate discarded mutations by pass and reason."""
    severity_by_reason = {
        "runtime_validation_failed": "high",
        "structural_validation_failed": "high",
        "symbolic_validation_failed": "high",
        "validation_failed": "high",
        "rollback": "medium",
        "skip_invalid_pass": "medium",
        "skip_invalid_mutation": "low",
        "unknown": "low",
    }
    severity_order = ROLLBACK_SEVERITY_ORDER
    by_pass: dict[str, int] = {}
    by_reason: dict[str, int] = {}
    by_pass_reason: dict[str, dict[str, int]] = {}

    for mutation in discarded_mutations:
        pass_name = str(mutation.get("pass_name", "unknown"))
        reason = str(mutation.get("discard_reason", "unknown"))
        by_pass[pass_name] = by_pass.get(pass_name, 0) + 1
        by_reason[reason] = by_reason.get(reason, 0) + 1
        pass_reason = by_pass_reason.setdefault(pass_name, {})
        pass_reason[reason] = pass_reason.get(reason, 0) + 1

    rows: list[dict[str, Any]] = [
        {
            "pass_name": pass_name,
            "discarded_count": count,
            "impact_severity": min(
                (severity_by_reason.get(reason, "low") for reason in by_pass_reason.get(pass_name, {})),
                key=lambda severity: severity_order.get(severity, 99),
                default="low",
            ),
            "reasons": dict(
                sorted(
                    by_pass_reason.get(pass_name, {}).items(),
                    key=lambda item: (-item[1], item[0]),
                )
            ),
        }
        for pass_name, count in by_pass.items()
    ]
    rows.sort(
        key=lambda item: (
            severity_order.get(str(item.get("impact_severity", "low")), 99),
            -int(item["discarded_count"]),
            item["pass_name"],
        )
    )
    return {
        "by_pass": rows,
        "by_reason": dict(sorted(by_reason.items(), key=lambda item: (-item[1], item[0]))),
        "by_impact": {
            severity: [dict(row) for row in rows if row.get("impact_severity") == severity]
            for severity in ("high", "medium", "low")
        },
        "by_pass_map": {
            row["pass_name"]: {
                "discarded_count": row["discarded_count"],
                "impact_severity": row.get("impact_severity", "low"),
                "reasons": dict(row["reasons"]),
            }
            for row in rows
        },
    }

