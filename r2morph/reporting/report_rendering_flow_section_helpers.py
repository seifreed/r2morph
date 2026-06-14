"""Pure line builders for flow rendering sections."""

from __future__ import annotations

from typing import Any


def build_degradation_summary_lines(
    *,
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    validation_policy: dict[str, Any] | None,
    degraded_passes: list[dict[str, Any]],
    degradation_roles: dict[str, int],
    symbolic_severity_rows: list[dict[str, Any]],
) -> list[str]:
    """Build the textual lines for the degradation section."""
    lines: list[str] = []
    if degraded_validation:
        lines.append(
            "[bold]Validation Mode Adjustment[/bold]: "
            f"requested={requested_validation_mode}, effective={effective_validation_mode}"
        )
        if validation_policy is not None:
            lines.append(
                f"  policy={validation_policy.get('policy', 'unknown')}, "
                f"reason={validation_policy.get('reason', 'unknown')}"
            )
            if degraded_passes:
                lines.append("[bold]Degraded Passes[/bold]:")
                for item in degraded_passes:
                    pass_name = item.get("pass_name", item.get("mutation", "unknown"))
                    confidence = item.get("confidence", "unknown")
                    lines.append(f"  [yellow]{pass_name}[/yellow]: symbolic confidence={confidence}")
            if degradation_roles:
                lines.append("[bold]Degradation Roles[/bold]:")
                for role, count in sorted(degradation_roles.items()):
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
    elif requested_validation_mode:
        lines.append(
            "[bold]Validation Mode[/bold]: "
            f"requested={requested_validation_mode}, effective={effective_validation_mode}"
        )
    return lines


def build_gate_summary_lines(
    *,
    gate_evaluation: dict[str, Any],
    gate_requested: dict[str, Any],
    gate_results: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
) -> list[str]:
    """Build the textual lines for the gate section."""
    if not gate_evaluation:
        return []

    lines = [
        f"[bold]Gate Evaluation[/bold]: all_passed={'yes' if gate_results.get('all_passed', True) else 'no'}"
    ]
    if gate_requested.get("min_severity") is not None:
        lines.append(
            "  "
            f"min_severity={gate_requested.get('min_severity')}, "
            f"passed={'yes' if gate_results.get('min_severity_passed', True) else 'no'}"
        )
    if gate_requested.get("require_pass_severity"):
        requested_rules = ", ".join(
            f"{item.get('pass_name')}<={item.get('max_severity')}"
            for item in gate_requested.get("require_pass_severity", [])
        )
        lines.append(
            "  "
            f"require_pass_severity={requested_rules}, "
            f"passed={'yes' if gate_results.get('require_pass_severity_passed', True) else 'no'}"
        )
        failures = list(gate_results.get("require_pass_severity_failures", []))
        if failures:
            lines.append("  failures: " + ", ".join(failures))
    lines.append(
        "[bold]Gate Failure Summary[/bold]: "
        f"min_severity_failed={'yes' if gate_failure_summary.get('min_severity_failed') else 'no'}, "
        f"require_pass_failures={gate_failure_summary.get('require_pass_severity_failure_count', 0)}"
    )
    severity_counts = gate_failure_summary.get("require_pass_severity_failures_by_expected_severity", {})
    if severity_counts:
        lines.append(
            "  expected_severity_counts="
            + ", ".join(f"{severity}:{count}" for severity, count in severity_counts.items())
        )
    if gate_failure_severity_priority:
        lines.append(
            "  expected_severity_priority="
            + ", ".join(f"{row.get('severity')}:{row.get('failure_count')}" for row in gate_failure_severity_priority)
        )
    pass_failure_map = gate_failure_summary.get("require_pass_severity_failures_by_pass", {})
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
