"""Mismatch detail assembly for report views."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_view_projections import _build_category_views, _summarize_rows


def build_mismatch_detail(
    observable_mismatch_priority: list[dict[str, Any]],
    mismatch_rows: list[dict[str, Any]],
    mismatch_by_pass: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build the only_mismatches detail section."""
    return {
        "priority": [dict(row) for row in observable_mismatch_priority],
        "by_pass": mismatch_by_pass,
        **_build_category_views(
            mismatch_rows,
            compact_fields=[
                "pass_name",
                "mismatch_count",
                "severity",
                "role",
                "symbolic_confidence",
                "degraded_execution",
                "region_count",
                "region_mismatch_count",
                "region_exit_match_count",
                "compact_region",
            ],
        ),
        "rows": mismatch_rows,
        "compact_summary": {
            **_summarize_rows(
                mismatch_rows,
                ["mismatch_count", "region_count", "region_mismatch_count", "region_exit_match_count"],
            ),
            "degraded_pass_count": sum(1 for row in mismatch_rows if row.get("degraded_execution")),
        },
        "summary": {
            **_summarize_rows(
                mismatch_rows,
                ["mismatch_count", "region_count", "region_mismatch_count", "region_exit_match_count"],
            ),
            "degraded_pass_count": sum(1 for row in mismatch_rows if row.get("degraded_execution")),
            "trigger_pass_count": sum(1 for row in mismatch_rows if row.get("degradation_triggered_by_pass")),
        },
    }
