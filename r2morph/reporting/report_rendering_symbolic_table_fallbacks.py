"""Fallback policy helpers for symbolic report table rendering."""

from __future__ import annotations

from typing import Any


def build_symbolic_severity_fallback_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Build severity rows from pass evidence when the primary severity payload is absent.
    """
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
    return severity_rows
