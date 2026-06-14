"""Validation-adjustment detail assembly for report views."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_view_projections import _build_category_views


def build_validation_adjustments_detail(degraded_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the validation_adjustments detail section."""
    shared = {
        "degraded_validation": bool(degraded_rows),
        "row_count": len(degraded_rows),
        "trigger_count": sum(1 for row in degraded_rows if row.get("triggered_adjustment")),
        "degraded_execution_count": sum(1 for row in degraded_rows if row.get("executed_under_degraded_mode")),
        "gate_failure_count": sum(int(row.get("gate_failure_count", 0)) for row in degraded_rows),
        "passes": [str(row.get("pass_name")) for row in degraded_rows if row.get("pass_name")],
    }
    return {
        "rows": degraded_rows,
        "by_pass": {str(row.get("pass_name")): dict(row) for row in degraded_rows if row.get("pass_name")},
        **_build_category_views(
            degraded_rows,
            compact_fields=[
                "pass_name",
                "role",
                "triggered_adjustment",
                "executed_under_degraded_mode",
                "gate_failure_count",
            ],
        ),
        "summary": {
            "requested_validation_mode": next(
                (row.get("requested_validation_mode") for row in degraded_rows if row.get("requested_validation_mode")),
                None,
            ),
            "effective_validation_mode": next(
                (row.get("effective_validation_mode") for row in degraded_rows if row.get("effective_validation_mode")),
                None,
            ),
            **shared,
        },
        "compact_summary": shared,
    }
