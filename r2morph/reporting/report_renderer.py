"""Legacy report renderer facade.

The modern reporting stack renders through :mod:`r2morph.reporting.report_rendering`
and its split helper modules. This compatibility layer keeps the historical
``ConsoleRenderer`` and ``ReportRenderer`` entry points available while routing
the shared rendering paths through the modular implementation.
"""

from __future__ import annotations

from typing import Any

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
        summary = payload.get("summary", {})

        if only_failed_gates:
            self._console_renderer.render_gate_failure_summary(
                payload.get("gate_failures", {}),
                payload.get("gate_failure_priority", []),
            )
            return

        if only_mismatches:
            self._render_mismatches_only(payload, summary)
            return

        self._render_full_report(payload, summary, summary_only)

    def _render_mismatches_only(
        self,
        payload: dict[str, Any],
        summary: dict[str, Any],
    ) -> None:
        """Render only the mismatches section of a report."""
        symbolic_overview = summary.get("symbolic_overview", {})
        mismatch_rows = []

        for mutation in payload.get("mutations", []):
            metadata = mutation.get("metadata", {})
            if not metadata.get("symbolic_observable_check_performed"):
                continue
            if metadata.get("symbolic_observable_equivalent", False):
                continue
            pass_name = mutation.get("pass_name", "unknown")
            start_addr = mutation.get("start_address")
            end_addr = mutation.get("end_address")
            observables = list(metadata.get("symbolic_observable_mismatches", []))
            mismatch_rows.append((pass_name, start_addr, end_addr, observables))

        self._console_renderer.render_symbolic_sections(
            symbolic_requested=int(symbolic_overview.get("symbolic_requested", 0)),
            observable_match=int(symbolic_overview.get("observable_match", 0)),
            observable_mismatch=int(symbolic_overview.get("observable_mismatch", 0)),
            bounded_only=int(symbolic_overview.get("bounded_only", 0)),
            observable_not_run=int(symbolic_overview.get("without_coverage", 0)),
            summary=summary,
            pass_results={},
            by_pass={},
            mismatch_rows=mismatch_rows,
        )

    def _render_full_report(
        self,
        payload: dict[str, Any],
        summary: dict[str, Any],
        summary_only: bool,
    ) -> None:
        """Render the full report with all sections."""
        pass_results = payload.get("pass_results", {})

        self._console_renderer.render_pass_evidence_table(pass_results)

        if payload.get("gate_failures"):
            self._console_renderer.render_gate_failure_summary(
                payload.get("gate_failures", {}),
                payload.get("gate_failure_priority", []),
            )

        if summary.get("degradation_roles"):
            self._console_renderer.render_degradation_summary(
                payload.get("validation_policy", {}),
                summary.get("degradation_roles", {}),
            )

        if not summary_only:
            self._render_mismatches_only(payload, summary)
