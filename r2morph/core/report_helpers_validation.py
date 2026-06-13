"""Validation-policy report helpers extracted from core.report_helpers."""

from __future__ import annotations

from typing import Any


def _build_pass_validation_context(
    pass_name: str,
    *,
    requested_mode: str,
    effective_mode: str,
    validation_policy: dict[str, Any] | None,
) -> dict[str, Any]:
    """Describe how validation mode applied to an individual pass."""
    limited_passes = list((validation_policy or {}).get("limited_passes", []))
    trigger = next((item for item in limited_passes if item.get("pass_name") == pass_name), None)
    degraded_execution = requested_mode != effective_mode
    if trigger is not None:
        role = "degradation-trigger"
    elif degraded_execution:
        role = "executed-under-degraded-mode"
    else:
        role = "requested-mode"
    return {
        "requested_validation_mode": requested_mode,
        "effective_validation_mode": effective_mode,
        "degraded_execution": degraded_execution,
        "degradation_triggered_by_pass": trigger is not None,
        "degradation_policy": (validation_policy or {}).get("policy"),
        "degradation_reason": (validation_policy or {}).get("reason"),
        "degradation_trigger": trigger,
        "role": role,
    }


def _enrich_validation_policy(
    validation_policy: dict[str, Any] | None,
    pass_results: dict[str, Any],
) -> dict[str, Any] | None:
    """Attach per-pass role metadata to validation policy for machine-readable consumers."""
    if validation_policy is None:
        return None

    enriched = dict(validation_policy)
    enriched_limited_passes = []
    for item in validation_policy.get("limited_passes", []):
        entry = dict(item)
        pass_name = entry.get("pass_name")
        role = None
        if pass_name is not None:
            role = pass_results.get(pass_name, {}).get("validation_context", {}).get("role")
        if role is not None:
            entry["role"] = role
        enriched_limited_passes.append(entry)
    enriched["limited_passes"] = enriched_limited_passes
    return enriched


def _summarize_degradation_roles(
    pass_results: dict[str, Any],
) -> dict[str, int]:
    """Aggregate degradation role counts across pass validation contexts."""
    counts: dict[str, int] = {}
    for pass_result in pass_results.values():
        role = pass_result.get("validation_context", {}).get("role")
        if not role:
            continue
        counts[role] = counts.get(role, 0) + 1
    return counts


def _summarize_validation_role_rows(
    pass_validation_context: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build a compact summary of validation role per pass."""
    rows = []
    for pass_name, context in pass_validation_context.items():
        rows.append(
            {
                "pass_name": pass_name,
                "role": context.get("role", "unknown"),
                "requested_validation_mode": context.get("requested_validation_mode", "off"),
                "effective_validation_mode": context.get("effective_validation_mode", "off"),
                "degraded_execution": bool(context.get("degraded_execution", False)),
            }
        )
    rows.sort(
        key=lambda item: (
            0 if item["role"] == "degradation-trigger" else 1,
            0 if item["role"] == "executed-under-degraded-mode" else 1,
            item["pass_name"],
        )
    )
    return rows


def _build_validation_role_map(
    rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Index validation role rows by pass name."""
    return {str(row.get("pass_name")): dict(row) for row in rows if row.get("pass_name")}


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
