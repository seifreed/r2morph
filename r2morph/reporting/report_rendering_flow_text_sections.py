"""Flow-oriented text report rendering helpers."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from r2morph.reporting.report_rendering_primitives import _get_console
from r2morph.reporting.report_rendering_tables import (
    render_degradation_sections,
    render_only_pass_sections,
)


def render_gate_evaluation_sections(
    gate_evaluation: dict[str, Any],
    gate_requested: dict[str, Any],
    gate_results: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """Render persisted gate evaluation and failure sections."""
    c = console or _get_console()

    if not gate_evaluation:
        return

    c.print("[bold]Gate Evaluation[/bold]: " f"all_passed={'yes' if gate_results.get('all_passed', True) else 'no'}")

    if gate_requested.get("min_severity") is not None:
        c.print(
            "  "
            f"min_severity={gate_requested.get('min_severity')}, "
            f"passed={'yes' if gate_results.get('min_severity_passed', True) else 'no'}"
        )

    if gate_requested.get("require_pass_severity"):
        requested_rules = ", ".join(
            f"{item.get('pass_name')}<={item.get('max_severity')}"
            for item in gate_requested.get("require_pass_severity", [])
        )
        c.print(
            "  "
            f"require_pass_severity={requested_rules}, "
            f"passed={'yes' if gate_results.get('require_pass_severity_passed', True) else 'no'}"
        )
        failures = list(gate_results.get("require_pass_severity_failures", []))
        if failures:
            c.print("  failures: " + ", ".join(failures))

    c.print(
        "[bold]Gate Failure Summary[/bold]: "
        f"min_severity_failed={'yes' if gate_failure_summary.get('min_severity_failed') else 'no'}, "
        f"require_pass_failures={gate_failure_summary.get('require_pass_severity_failure_count', 0)}"
    )

    severity_counts = gate_failure_summary.get("require_pass_severity_failures_by_expected_severity", {})
    if severity_counts:
        c.print(
            "  expected_severity_counts="
            + ", ".join(f"{severity}:{count}" for severity, count in severity_counts.items())
        )

    if gate_failure_severity_priority:
        c.print(
            "  expected_severity_priority="
            + ", ".join(f"{row.get('severity')}:{row.get('failure_count')}" for row in gate_failure_severity_priority)
        )

    pass_failure_map = gate_failure_summary.get("require_pass_severity_failures_by_pass", {})
    if pass_failure_map:
        c.print("[bold]Gate Failure By Pass[/bold]:")
        for row in gate_failure_priority or [
            {
                "pass_name": pass_name,
                "failure_count": len(failures),
                "strictest_expected_severity": "unknown",
                "failures": list(failures),
            }
            for pass_name, failures in pass_failure_map.items()
        ]:
            pass_name = row.get("pass_name", "unknown")
            failures_list = list(row.get("failures", []))
            failure_count = row.get("failure_count", len(failures_list))
            strictest = row.get("strictest_expected_severity", "unknown")
            c.print(
                f"  [yellow]{pass_name}[/yellow] "
                f"(count={failure_count}, strictest_expected={strictest}): " + ", ".join(failures_list)
            )


def render_general_report_sections(
    filtered_summary: dict[str, Any],
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    degraded_passes: list[dict[str, Any]],
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    validation_policy: dict[str, Any] | None,
    gate_evaluation: dict[str, Any],
    gate_requested: dict[str, Any],
    gate_results: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    degradation_roles: dict[str, int],
    resolved_only_pass: str | None,
    *,
    console: Console | None = None,
) -> None:
    """Render general report flow sections."""
    c = console or _get_console()

    if resolved_only_pass:
        c.print(f"\n[bold cyan]Filtered to Pass: {resolved_only_pass}[/bold cyan]")

    if degraded_validation:
        c.print(
            f"\n[yellow]Validation Mode Degraded:[/yellow] "
            f"requested={requested_validation_mode}, effective={effective_validation_mode}"
        )

    if gate_evaluation:
        render_gate_evaluation_sections(
            gate_evaluation=gate_evaluation,
            gate_requested=gate_requested,
            gate_results=gate_results,
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            console=c,
        )

    if degradation_roles:
        render_degradation_sections(
            {"degraded_validation": degraded_validation, "roles": degradation_roles},
            console=c,
        )


def render_general_only_pass_sections(
    pass_name: str,
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    resolved_only_pass: str | None,
    *,
    console: Console | None = None,
) -> None:
    """Render only-pass sections for general report."""
    c = console or _get_console()

    if not resolved_only_pass:
        return

    c.print(f"\n[bold cyan]Single Pass Report: {pass_name}[/bold cyan]")

    pass_result = pass_results.get(pass_name, {})
    if pass_result:
        evidence = pass_result.get("evidence_summary", {})
        if evidence:
            render_only_pass_sections(pass_name, {"evidence_summary": evidence}, console=c)
