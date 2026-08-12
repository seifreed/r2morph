"""Filtered-summary degradation section builders."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_builder_models import ReportContext
from r2morph.reporting.report_view_resolution import _resolve_general_report_views


def _persisted_adjustment_sections(adjustments: dict[str, Any]) -> dict[str, Any]:
    section: dict[str, Any] = {}
    for source_key, target_key, converter in (
        ("by_pass", "validation_adjustment_by_pass", dict),
        ("compact_by_pass", "validation_adjustment_compact_by_pass", dict),
        ("rows", "validation_adjustment_rows", list),
        ("compact_rows", "validation_adjustment_compact_rows", list),
        ("summary", "validation_adjustment_summary", dict),
    ):
        if adjustments.get(source_key):
            section[target_key] = converter(adjustments[source_key])

    compact_summary = adjustments.get("compact_summary") or adjustments.get("summary")
    if compact_summary:
        section["validation_adjustment_compact_summary"] = dict(compact_summary)
    return section


def _general_adjustment_sections(degradation: dict[str, Any]) -> dict[str, Any]:
    section: dict[str, Any] = {}
    if degradation.get("rows"):
        section["validation_adjustment_rows"] = list(degradation["rows"])
    if degradation.get("compact_rows"):
        section["validation_adjustment_compact_rows"] = list(degradation["compact_rows"])
    if degradation.get("summary"):
        summary = dict(degradation["summary"])
        section["validation_adjustment_summary"] = summary
        section["validation_adjustment_compact_summary"] = summary
    return section


def _build_filtered_summary_degradation_sections(
    context: ReportContext,
    degraded_passes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build filtered_summary degradation/validation-mode sections."""
    summary = context.summary
    resolved_general_views = _resolve_general_report_views(summary)
    report_views = resolved_general_views["report_views"]
    validation_adjustments = dict(summary.get("validation_adjustments", {}) or {})
    general_degradation = resolved_general_views["general_degradation"]
    persisted_adjustments = dict(report_views.get("validation_adjustments", {}) or {})
    degradation_roles = dict(summary.get("degradation_roles", {}) or {})
    section: dict[str, Any] = {
        "requested_validation_mode": context.requested_validation_mode,
        "validation_mode": context.effective_validation_mode,
        "degraded_validation": context.degraded_validation,
        "degraded_passes": degraded_passes,
        "degradation_roles": degradation_roles,
    }
    if context.validation_policy is not None:
        section["validation_policy"] = context.validation_policy
    if general_degradation.get("summary"):
        section["validation_adjustments"] = dict(general_degradation.get("summary", {}))
    elif validation_adjustments:
        section["validation_adjustments"] = validation_adjustments
    if persisted_adjustments:
        section.update(_persisted_adjustment_sections(persisted_adjustments))
    elif general_degradation:
        section.update(_general_adjustment_sections(general_degradation))
    elif validation_adjustments:
        section["validation_adjustment_compact_summary"] = {
            "requested_validation_mode": context.requested_validation_mode,
            "effective_validation_mode": context.effective_validation_mode,
            "degraded_validation": context.degraded_validation,
        }
    return section
