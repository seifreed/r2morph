"""Filtered-summary degradation section builders."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_view_resolution import _resolve_general_report_views


def _build_filtered_summary_degradation_sections(
    *,
    summary: dict[str, Any],
    validation_policy: dict[str, Any] | None,
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    degraded_passes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build filtered_summary degradation/validation-mode sections."""
    resolved_general_views = _resolve_general_report_views(summary)
    report_views = resolved_general_views["report_views"]
    validation_adjustments = dict(summary.get("validation_adjustments", {}) or {})
    general_degradation = resolved_general_views["general_degradation"]
    persisted_adjustments = dict(report_views.get("validation_adjustments", {}) or {})
    degradation_roles = dict(summary.get("degradation_roles", {}) or {})
    section: dict[str, Any] = {
        "requested_validation_mode": requested_validation_mode,
        "validation_mode": effective_validation_mode,
        "degraded_validation": degraded_validation,
        "degraded_passes": degraded_passes,
        "degradation_roles": degradation_roles,
    }
    if validation_policy is not None:
        section["validation_policy"] = validation_policy
    if general_degradation.get("summary"):
        section["validation_adjustments"] = dict(general_degradation.get("summary", {}))
    elif validation_adjustments:
        section["validation_adjustments"] = validation_adjustments
    if persisted_adjustments:
        if persisted_adjustments.get("by_pass"):
            section["validation_adjustment_by_pass"] = dict(persisted_adjustments.get("by_pass", {}))
        if persisted_adjustments.get("compact_by_pass"):
            section["validation_adjustment_compact_by_pass"] = dict(persisted_adjustments.get("compact_by_pass", {}))
        if persisted_adjustments.get("rows"):
            section["validation_adjustment_rows"] = list(persisted_adjustments.get("rows", []))
        if persisted_adjustments.get("compact_rows"):
            section["validation_adjustment_compact_rows"] = list(persisted_adjustments.get("compact_rows", []))
        if persisted_adjustments.get("summary"):
            section["validation_adjustment_summary"] = dict(persisted_adjustments.get("summary", {}))
        if persisted_adjustments.get("compact_summary"):
            section["validation_adjustment_compact_summary"] = dict(persisted_adjustments.get("compact_summary", {}))
        elif persisted_adjustments.get("summary"):
            section["validation_adjustment_compact_summary"] = dict(persisted_adjustments.get("summary", {}))
    elif general_degradation:
        if general_degradation.get("rows"):
            section["validation_adjustment_rows"] = list(general_degradation.get("rows", []))
        if general_degradation.get("compact_rows"):
            section["validation_adjustment_compact_rows"] = list(general_degradation.get("compact_rows", []))
        if general_degradation.get("summary"):
            section["validation_adjustment_summary"] = dict(general_degradation.get("summary", {}))
            section["validation_adjustment_compact_summary"] = dict(general_degradation.get("summary", {}))
    elif validation_adjustments:
        section["validation_adjustment_compact_summary"] = {
            "requested_validation_mode": requested_validation_mode,
            "effective_validation_mode": effective_validation_mode,
            "degraded_validation": degraded_validation,
        }
    return section
