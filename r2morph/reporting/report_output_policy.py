"""Output and exit-policy helpers for filtered reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from r2morph.reporting.report_gate_helpers import _gate_failure_result_count, _severity_threshold_met
from r2morph.reporting.report_output_io import emit_report_payload

console = Console()


def _report_view_has_results(
    *,
    mutation_count: int,
    only_failed_gates: bool,
    failed_gates: bool,
    gate_failure_count: int | None = None,
    only_risky_passes: bool = False,
    risky_pass_count: int | None = None,
    pass_count: int | None = None,
) -> bool:
    """Determine whether a filtered report view should count as non-empty."""
    if only_failed_gates:
        if gate_failure_count is not None:
            return gate_failure_count > 0
        return failed_gates
    if only_risky_passes and risky_pass_count is not None:
        return risky_pass_count > 0
    if pass_count is not None:
        return pass_count > 0
    return mutation_count > 0


def _emit_report_payload(
    *,
    filtered_payload: dict[str, Any],
    output: Path | None,
    summary_only: bool,
) -> None:
    """Write and/or print a filtered report payload."""
    emit_report_payload(
        filtered_payload=filtered_payload, output=output, summary_only=summary_only, console_instance=console
    )


def _enforce_report_requirements(
    *,
    require_results: bool,
    severity_rows: list[dict[str, Any]],
    min_severity_rank: int | None,
    mutation_count: int,
    only_failed_gates: bool,
    failed_gates: bool,
    gate_failure_count: int | None,
    only_risky_passes: bool,
    risky_pass_count: int,
    pass_count: int,
) -> None:
    """Apply report exit-code policy for empty views or missing severity."""
    severity_ok = _severity_threshold_met(severity_rows, min_severity_rank)
    has_results = _report_view_has_results(
        mutation_count=mutation_count,
        only_failed_gates=only_failed_gates,
        failed_gates=failed_gates,
        gate_failure_count=gate_failure_count,
        only_risky_passes=only_risky_passes,
        risky_pass_count=risky_pass_count,
        pass_count=pass_count,
    )
    if require_results and (not has_results or not severity_ok):
        raise typer.Exit(1)


def _finalize_report_output(
    *,
    filtered_payload: dict[str, Any],
    output: Path | None,
    summary_only: bool,
    require_results: bool,
    min_severity_rank: int | None,
    only_failed_gates: bool,
    failed_gates: bool,
    only_expected_severity: str | None,
    resolved_only_pass_failure: str | None,
    only_risky_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
) -> None:
    """Emit a filtered report and enforce CLI exit policies."""
    filtered_summary = filtered_payload.get("filtered_summary", {})
    _emit_report_payload(
        filtered_payload=filtered_payload,
        output=output,
        summary_only=summary_only,
    )
    _enforce_report_requirements(
        require_results=require_results,
        severity_rows=filtered_summary.get("symbolic_severity_by_pass", []),
        min_severity_rank=min_severity_rank,
        mutation_count=len(filtered_payload.get("mutations", [])),
        only_failed_gates=only_failed_gates,
        failed_gates=failed_gates,
        gate_failure_count=(
            int(filtered_summary.get("gate_failures", {}).get("require_pass_severity_failure_count", 0))
            if (only_expected_severity is not None or resolved_only_pass_failure is not None)
            else _gate_failure_result_count(filtered_summary.get("gate_failures", {})) if only_failed_gates else None
        ),
        only_risky_passes=(
            only_risky_passes
            or only_structural_risk
            or only_symbolic_risk
            or only_uncovered_passes
            or only_covered_passes
            or only_clean_passes
        ),
        risky_pass_count=(
            len(filtered_summary.get("passes", []))
            if (
                only_risky_passes
                or only_structural_risk
                or only_symbolic_risk
                or only_uncovered_passes
                or only_covered_passes
                or only_clean_passes
            )
            else len(filtered_summary.get("pass_evidence", []))
        ),
        pass_count=len(filtered_summary.get("passes", [])),
    )
