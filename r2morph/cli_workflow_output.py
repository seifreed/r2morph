"""CLI workflow output helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from r2morph.reporting.report_gate_helpers import (
    _attach_gate_evaluation,
    _pass_severity_requirements_met,
    _severity_threshold_met,
)

console = Console()


def print_mutation_summary(result: dict[str, Any], output_path: Path | None = None) -> None:
    table = Table(title="Mutation Engine Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    requested_mode = result.get("requested_validation_mode", result.get("validation_mode", "off"))
    effective_mode = result.get("validation_mode", "off")
    table.add_row("Requested Validation", str(requested_mode))
    table.add_row("Effective Validation", str(effective_mode))
    table.add_row("Total Mutations", str(result.get("total_mutations", 0)))
    table.add_row("Passes Run", str(result.get("passes_run", 0)))
    table.add_row("Rolled Back Passes", str(result.get("rolled_back_passes", 0)))
    table.add_row("Discarded Mutations", str(result.get("discarded_mutations", 0)))
    table.add_row(
        "Validation Passed",
        "yes" if result.get("validation", {}).get("all_passed", False) else "no",
    )
    total_issues = result.get("validation", {}).get("total_issues", 0)
    table.add_row("Validation Issues", str(total_issues))
    for pass_name, pass_result in result.get("pass_results", {}).items():
        if "error" in pass_result:
            table.add_row(pass_name, f"[red]Error: {pass_result['error']}[/red]")
            continue
        rolled_back = ""
        if pass_result.get("rolled_back"):
            reason = pass_result.get("rollback_reason", "rollback")
            rolled_back = f" (rolled back: {reason})"
        table.add_row(
            pass_name,
            f"{pass_result.get('mutations_applied', 0)} mutations{rolled_back}",
        )

    console.print(table)
    if output_path is not None:
        console.print(f"\n[bold green]✓[/bold green] Binary saved to: {output_path}")


def evaluate_and_write_gates(
    *,
    report_payload: dict[str, Any],
    report_path: Path | None,
    min_severity: str | None,
    min_severity_rank: int | None,
    pass_severity_requirements: list[tuple[str, str, int]] | None,
    report_format: str = "json",
) -> None:
    """Evaluate severity gates, write report, and exit on failure."""
    severity_rows = list(report_payload.get("summary", {}).get("symbolic_severity_by_pass", []))
    min_severity_passed = _severity_threshold_met(severity_rows, min_severity_rank)
    pass_requirements_ok = True
    pass_requirement_failures: list[str] = []
    if pass_severity_requirements:
        pass_requirements_ok, pass_requirement_failures = _pass_severity_requirements_met(
            severity_rows,
            pass_severity_requirements,
        )
    report_payload = _attach_gate_evaluation(
        report_payload,
        min_severity=min_severity,
        min_severity_passed=min_severity_passed,
        require_pass_severity=pass_severity_requirements or [],
        require_pass_severity_passed=pass_requirements_ok,
        require_pass_severity_failures=pass_requirement_failures,
    )
    if report_path is not None:
        if report_format.lower() == "sarif":
            from r2morph.reporting.sarif_formatter import format_as_sarif

            sarif = format_as_sarif(
                report_payload.get("mutations", []),
                report_payload.get("validation", {}).get("results", []),
                report_payload.get("input", {}).get("path", ""),
            )
            report_path.write_text(sarif.to_json(), encoding="utf-8")
        else:
            report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
    if min_severity is not None and not min_severity_passed:
        console.print(f"[bold yellow]Severity gate failed:[/bold yellow] min_severity={min_severity}")
        raise typer.Exit(1)
    if min_severity is not None:
        console.print(f"[cyan]Severity gate passed:[/cyan] min_severity={min_severity}")
    if pass_severity_requirements and not pass_requirements_ok:
        console.print("[bold yellow]Pass severity gate failed:[/bold yellow] " + ", ".join(pass_requirement_failures))
        raise typer.Exit(1)
    if pass_severity_requirements:
        console.print(
            "[cyan]Pass severity gate passed:[/cyan] "
            + ", ".join(f"{pn}<={s}" for pn, s, _ in pass_severity_requirements)
        )
