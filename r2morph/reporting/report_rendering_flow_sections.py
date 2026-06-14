"""High-level flow rendering helpers extracted from report_rendering_sections."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_rendering_flow_section_helpers import (
    build_degradation_summary_lines,
    build_gate_summary_lines,
)
from r2morph.reporting.report_rendering_primitives import _get_console


def _render_degradation_sections(
    *,
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    validation_policy: dict[str, Any] | None,
    degraded_passes: list[dict[str, Any]],
    degradation_roles: dict[str, int],
    symbolic_severity_rows: list[dict[str, Any]],
) -> None:
    """Render validation-mode adjustment/degradation summary."""
    for line in build_degradation_summary_lines(
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        validation_policy=validation_policy,
        degraded_passes=degraded_passes,
        degradation_roles=degradation_roles,
        symbolic_severity_rows=symbolic_severity_rows,
    ):
        _get_console().print(line)


def _render_gate_sections(
    *,
    gate_evaluation: dict[str, Any],
    gate_requested: dict[str, Any],
    gate_results: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
) -> None:
    """Render persisted gate evaluation and failure sections."""
    for line in build_gate_summary_lines(
        gate_evaluation=gate_evaluation,
        gate_requested=gate_requested,
        gate_results=gate_results,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
    ):
        _get_console().print(line)
