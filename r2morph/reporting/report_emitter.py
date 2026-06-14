"""Compatibility wrappers for report emission and output policy."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console

from r2morph.reporting.report_output_policy import (
    _enforce_report_requirements as _enforce_report_requirements_impl,
)
from r2morph.reporting.report_output_policy import (
    _report_view_has_results as _report_view_has_results_impl,
)
from r2morph.reporting.report_output_policy import (
    _severity_threshold_met as _severity_threshold_met_impl,
)

console = Console()


def emit_report_payload(
    *,
    filtered_payload: dict[str, Any],
    output: Path | None,
    summary_only: bool,
    console_instance: Console | None = None,
) -> None:
    """Write and/or print a filtered report payload."""
    c = console_instance or console
    if output is not None:
        output.write_text(json.dumps(filtered_payload, indent=2), encoding="utf-8")
        c.print(f"[cyan]Filtered report written:[/cyan] {output}")
    if not summary_only:
        c.print_json(json.dumps(filtered_payload))


def enforce_report_requirements(
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
    _enforce_report_requirements_impl(
        require_results=require_results,
        severity_rows=severity_rows,
        min_severity_rank=min_severity_rank,
        mutation_count=mutation_count,
        only_failed_gates=only_failed_gates,
        failed_gates=failed_gates,
        gate_failure_count=gate_failure_count,
        only_risky_passes=only_risky_passes,
        risky_pass_count=risky_pass_count,
        pass_count=pass_count,
    )


def severity_threshold_met(severity_rows: list[dict[str, Any]], min_severity_rank: int | None) -> bool:
    """Check if severity threshold is met."""
    return _severity_threshold_met_impl(severity_rows=severity_rows, min_severity_rank=min_severity_rank)


def report_view_has_results(
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
    return _report_view_has_results_impl(
        mutation_count=mutation_count,
        only_failed_gates=only_failed_gates,
        failed_gates=failed_gates,
        gate_failure_count=gate_failure_count,
        only_risky_passes=only_risky_passes,
        risky_pass_count=risky_pass_count,
        pass_count=pass_count,
    )


def gate_failure_result_count(gate_failures: dict[str, Any]) -> int:
    """Return a non-zero count when any persisted gate failure is present."""
    from r2morph.reporting.report_gate_helpers import _gate_failure_result_count as _gate_failure_result_count_impl

    return _gate_failure_result_count_impl(gate_failures)
