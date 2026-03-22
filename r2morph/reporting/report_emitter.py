"""
Report emission functions extracted from cli.py.

This module handles writing and printing report payloads:
- Emit filtered reports to files or stdout
- Enforce report requirements for CI exit codes
"""

import json

from r2morph.reporting.gate_evaluator import SEVERITY_ORDER
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()


def emit_report_payload(
    *,
    filtered_payload: dict[str, Any],
    output: Path | None,
    summary_only: bool,
    console_instance: Console | None = None,
) -> None:
    """
    Write and/or print a filtered report payload.

    Args:
        filtered_payload: The filtered report payload dict
        output: Optional output file path
        summary_only: If True, don't print JSON to stdout
        console_instance: Optional Console instance (uses default if None)
    """
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
    """
    Apply report exit-code policy for empty views or missing severity.

    Raises typer.Exit(1) if requirements not met.

    Args:
        require_results: Whether to enforce non-empty results
        severity_rows: List of severity rows
        min_severity_rank: Minimum severity rank required
        mutation_count: Number of mutations
        only_failed_gates: Whether filtering to failed gates
        failed_gates: Whether gates failed
        gate_failure_count: Count of gate failures
        only_risky_passes: Whether filtering to risky passes
        risky_pass_count: Count of risky passes
        pass_count: Count of passes
    """
    import typer

    severity_ok = severity_threshold_met(severity_rows, min_severity_rank)
    has_results = report_view_has_results(
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


def severity_threshold_met(
    severity_rows: list[dict[str, Any]],
    min_severity_rank: int | None,
) -> bool:
    """
    Check if severity threshold is met.

    Args:
        severity_rows: List of severity rows
        min_severity_rank: Minimum severity rank required

    Returns:
        True if threshold met
    """
    if min_severity_rank is None:
        return True

    if not severity_rows:
        return False

    severity_order = SEVERITY_ORDER

    for row in severity_rows:
        severity = str(row.get("severity", "not-requested"))
        rank = severity_order.get(severity, 99)
        if rank <= min_severity_rank:
            return True

    return False


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
    """
    Determine whether a filtered report view should count as non-empty.

    Args:
        mutation_count: Number of mutations
        only_failed_gates: Whether filtering to failed gates
        failed_gates: Whether gates failed
        gate_failure_count: Count of gate failures
        only_risky_passes: Whether filtering to risky passes
        risky_pass_count: Count of risky passes
        pass_count: Count of passes

    Returns:
        True if view has results
    """
    if only_failed_gates:
        if gate_failure_count is not None:
            return gate_failure_count > 0
        return failed_gates

    if only_risky_passes and risky_pass_count is not None:
        return risky_pass_count > 0

    if pass_count is not None:
        return pass_count > 0

    return mutation_count > 0


def gate_failure_result_count(gate_failures: dict[str, Any]) -> int:
    """
    Return a non-zero count when any persisted gate failure is present.

    Args:
        gate_failures: Gate failures dict

    Returns:
        Count of failures
    """
    count = int(gate_failures.get("require_pass_severity_failure_count", 0) or 0)
    if gate_failures.get("min_severity_failed"):
        count += 1
    if gate_failures.get("all_passed") is False and count == 0:
        count = 1
    return count
