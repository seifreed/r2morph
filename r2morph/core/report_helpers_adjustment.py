"""Validation-adjustment report helpers extracted from core.report_helpers."""

from __future__ import annotations

from typing import Any


def _summarize_validation_adjustments(
    *,
    requested_mode: str,
    effective_mode: str,
    validation_policy: dict[str, Any] | None,
    validation_role_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarize validation mode adjustments for report consumers."""
    limited_passes = list((validation_policy or {}).get("limited_passes", []))
    trigger_passes = [item.get("pass_name", item.get("mutation", "unknown")) for item in limited_passes]
    degraded_passes = [
        row["pass_name"] for row in validation_role_rows if row.get("role") == "executed-under-degraded-mode"
    ]
    return {
        "requested_validation_mode": requested_mode,
        "effective_validation_mode": effective_mode,
        "degraded_validation": requested_mode != effective_mode,
        "policy": (validation_policy or {}).get("policy"),
        "reason": (validation_policy or {}).get("reason"),
        "trigger_passes": trigger_passes,
        "executed_under_degraded_mode_passes": degraded_passes,
    }


def _summarize_validation_adjustment_rows(
    validation_role_rows: list[dict[str, Any]],
    validation_adjustments: dict[str, Any],
    gate_failures: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Build a compact per-pass adjustment/gate view for report consumers."""
    failed_by_pass = dict((gate_failures or {}).get("require_pass_severity_failures_by_pass", {}))
    rows: list[dict[str, Any]] = []
    degraded_validation = bool(validation_adjustments.get("degraded_validation", False))
    trigger_passes = set(validation_adjustments.get("trigger_passes", []) or [])
    degraded_passes = set(validation_adjustments.get("executed_under_degraded_mode_passes", []) or [])
    for row in validation_role_rows:
        pass_name = str(row.get("pass_name", ""))
        if not pass_name:
            continue
        rows.append(
            {
                "pass_name": pass_name,
                "role": row.get("role", "requested-mode"),
                "degraded_validation": degraded_validation,
                "triggered_adjustment": pass_name in trigger_passes,
                "executed_under_degraded_mode": pass_name in degraded_passes,
                "gate_failures": list(failed_by_pass.get(pass_name, [])),
                "gate_failure_count": len(failed_by_pass.get(pass_name, [])),
            }
        )
    return rows
