"""Legacy report renderer facade.

The modern reporting stack renders through :mod:`r2morph.reporting.report_rendering`
and its split helper modules. This compatibility layer keeps the historical
``ConsoleRenderer`` and ``ReportRenderer`` entry points available while routing
the shared rendering paths through the modular implementation.
"""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_renderer_orchestrator import render_report as _render_report_impl
from r2morph.reporting.report_renderer_tables import (
    render_filtered_summary_table,
    render_mismatch_table,
    render_pass_evidence_table,
)
from r2morph.reporting.report_rendering import (
    render_degradation_sections,
    render_gate_sections,
    render_symbolic_sections,
)


class ConsoleRenderer:
    """Compatibility wrapper around the modular report rendering helpers."""

    def __init__(self, console: Any):
        self._console = console

    def render_symbolic_sections(
        self,
        symbolic_requested: int,
        observable_match: int,
        observable_mismatch: int,
        bounded_only: int,
        observable_not_run: int,
        summary: dict[str, Any],
        pass_results: dict[str, Any],
        by_pass: dict[str, dict[str, int]],
        mismatch_rows: list[tuple[str, int | None, int | None, list[str]]],
    ) -> None:
        """Render symbolic validation summary sections."""
        if symbolic_requested == 0:
            return

        render_symbolic_sections(
            symbolic_requested=symbolic_requested,
            observable_match=observable_match,
            observable_mismatch=observable_mismatch,
            bounded_only=bounded_only,
            without_coverage=observable_not_run,
            console=self._console,
        )

        if mismatch_rows:
            render_mismatch_table(self._console, mismatch_rows)

    def render_pass_evidence_table(
        self,
        pass_results: dict[str, Any],
    ) -> None:
        """Render a table of pass evidence summaries."""
        render_pass_evidence_table(self._console, pass_results)

    def render_gate_failure_summary(
        self,
        gate_failure_summary: dict[str, Any],
        gate_failure_priority: list[dict[str, Any]],
    ) -> None:
        """Render a summary of gate failures."""
        render_gate_sections(
            gate_failure_summary,
            gate_failure_priority,
            console=self._console,
        )

    def render_degradation_summary(
        self,
        validation_adjustments: dict[str, Any],
        degradation_roles: dict[str, int],
    ) -> None:
        """Render a summary of validation mode degradations."""
        render_degradation_sections(
            {"degraded_validation": validation_adjustments.get("degraded_validation"), "roles": degradation_roles},
            console=self._console,
        )

    def render_filtered_summary(
        self,
        filtered_summary: dict[str, Any],
        only_mismatches: bool = False,
        only_failed_gates: bool = False,
    ) -> None:
        """Render a filtered report summary."""
        render_filtered_summary_table(
            self._console,
            filtered_summary,
            only_mismatches=only_mismatches,
            only_failed_gates=only_failed_gates,
        )


class ReportRenderer:
    """Main report renderer that coordinates console output."""

    def __init__(self, console: Any):
        self._console_renderer = ConsoleRenderer(console)

    def render_report(
        self,
        payload: dict[str, Any],
        summary_only: bool = False,
        only_mismatches: bool = False,
        only_failed_gates: bool = False,
    ) -> None:
        """Render a complete report payload."""
        _render_report_impl(
            self._console_renderer,
            payload,
            summary_only=summary_only,
            only_mismatches=only_mismatches,
            only_failed_gates=only_failed_gates,
        )
