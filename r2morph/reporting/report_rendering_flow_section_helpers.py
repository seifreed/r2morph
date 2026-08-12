"""Pure line builders for flow rendering sections."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_context import GateState, ValidationState


def build_degradation_summary_lines(
    validation: ValidationState,
    symbolic_severity_rows: list[dict[str, Any]],
) -> list[str]:
    """Build the textual lines for the degradation section."""
    lines: list[str] = []
    if validation.degraded_validation:
        lines.append(
            "[bold]Validation Mode Adjustment[/bold]: "
            f"requested={validation.requested_validation_mode}, "
            f"effective={validation.effective_validation_mode}"
        )
        if validation.validation_policy is not None:
            lines.append(
                f"  policy={validation.validation_policy.get('policy', 'unknown')}, "
                f"reason={validation.validation_policy.get('reason', 'unknown')}"
            )
            if validation.degraded_passes:
                lines.append("[bold]Degraded Passes[/bold]:")
                for item in validation.degraded_passes:
                    pass_name = item.get("pass_name", item.get("mutation", "unknown"))
                    confidence = item.get("confidence", "unknown")
                    lines.append(f"  [yellow]{pass_name}[/yellow]: symbolic confidence={confidence}")
            if validation.degradation_roles:
                lines.append("[bold]Degradation Roles[/bold]:")
                for role, count in sorted(validation.degradation_roles.items()):
                    lines.append(f"  {role}: {count}")
            if symbolic_severity_rows:
                lines.append("[bold]Degraded Severity Priority[/bold]:")
                for row in symbolic_severity_rows:
                    lines.append(
                        f"  [cyan]{row['pass_name']}[/cyan]: "
                        f"severity={row.get('severity', 'unknown')}, "
                        f"issue_count={row.get('issue_count', 0)}, "
                        f"symbolic_requested={row.get('symbolic_requested', 0)}"
                    )
    elif validation.requested_validation_mode:
        lines.append(
            "[bold]Validation Mode[/bold]: "
            f"requested={validation.requested_validation_mode}, "
            f"effective={validation.effective_validation_mode}"
        )
    return lines


def build_gate_summary_lines(
    gates: GateState,
    gate_failure_priority: list[dict[str, Any]],
) -> list[str]:
    """Build the textual lines for the gate section."""
    if not gates.gate_evaluation:
        return []

    lines = [
        "[bold]Gate Evaluation[/bold]: " f"all_passed={'yes' if gates.gate_results.get('all_passed', True) else 'no'}"
    ]
    if gates.gate_requested.get("min_severity") is not None:
        lines.append(
            "  "
            f"min_severity={gates.gate_requested.get('min_severity')}, "
            f"passed={'yes' if gates.gate_results.get('min_severity_passed', True) else 'no'}"
        )
    if gates.gate_requested.get("require_pass_severity"):
        requested_rules = ", ".join(
            f"{item.get('pass_name')}<={item.get('max_severity')}"
            for item in gates.gate_requested.get("require_pass_severity", [])
        )
        lines.append(
            "  "
            f"require_pass_severity={requested_rules}, "
            f"passed={'yes' if gates.gate_results.get('require_pass_severity_passed', True) else 'no'}"
        )
        failures = list(gates.gate_results.get("require_pass_severity_failures", []))
        if failures:
            lines.append("  failures: " + ", ".join(failures))
    lines.append(
        "[bold]Gate Failure Summary[/bold]: "
        f"min_severity_failed={'yes' if gates.gate_failure_summary.get('min_severity_failed') else 'no'}, "
        "require_pass_failures="
        f"{gates.gate_failure_summary.get('require_pass_severity_failure_count', 0)}"
    )
    severity_counts = gates.gate_failure_summary.get("require_pass_severity_failures_by_expected_severity", {})
    if severity_counts:
        lines.append(
            "  expected_severity_counts="
            + ", ".join(f"{severity}:{count}" for severity, count in severity_counts.items())
        )
    if gates.gate_failure_severity_priority:
        lines.append(
            "  expected_severity_priority="
            + ", ".join(
                f"{row.get('severity')}:{row.get('failure_count')}" for row in gates.gate_failure_severity_priority
            )
        )
    pass_failure_map = gates.gate_failure_summary.get("require_pass_severity_failures_by_pass", {})
    if pass_failure_map:
        lines.append("[bold]Gate Failure By Pass[/bold]:")
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
            failures = list(row.get("failures", []))
            failure_count = row.get("failure_count", len(failures))
            strictest = row.get("strictest_expected_severity", "unknown")
            lines.append(
                f"  [yellow]{pass_name}[/yellow] "
                f"(count={failure_count}, strictest_expected={strictest}): " + ", ".join(failures)
            )
    return lines
