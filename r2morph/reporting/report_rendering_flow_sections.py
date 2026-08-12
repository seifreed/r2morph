"""High-level flow rendering helpers extracted from report_rendering_sections."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_context import GateState, ValidationState
from r2morph.reporting.report_rendering_flow_section_helpers import (
    build_degradation_summary_lines,
    build_gate_summary_lines,
)
from r2morph.reporting.report_rendering_primitives import _get_console


def _render_degradation_sections(
    validation: ValidationState,
    symbolic_severity_rows: list[dict[str, Any]],
) -> None:
    """Render validation-mode adjustment/degradation summary."""
    for line in build_degradation_summary_lines(
        validation,
        symbolic_severity_rows,
    ):
        _get_console().print(line)


def _render_gate_sections(
    gates: GateState,
    gate_failure_priority: list[dict[str, Any]],
) -> None:
    """Render persisted gate evaluation and failure sections."""
    for line in build_gate_summary_lines(
        gates,
        gate_failure_priority,
    ):
        _get_console().print(line)
