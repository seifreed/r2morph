"""
Console rendering functions extracted from cli.py.

This module handles all rich console rendering for reports:
- General report sections
- Pass capabilities and validation contexts
- Symbolic sections and mismatches
- Gate and degradation sections
"""

from typing import Any

from rich.console import Console
from rich.table import Table

CONSOLE = Console()


def create_table(title: str, columns: list[tuple[str, str]]) -> Table:
    """
    Create a styled table with columns.

    Args:
        title: Table title
        columns: List of (column_name, style) tuples

    Returns:
        Configured Table instance
    """
    table = Table(title=title)
    for name, style in columns:
        table.add_column(name, style=style)
    return table


def render_pass_capabilities(
    capabilities: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """
    Render pass capabilities table.

    Args:
        capabilities: List of capability dictionaries
        console: Optional console instance (uses default if None)
    """
    if not capabilities:
        return

    c = console or CONSOLE
    table = create_table(
        "Pass Capabilities",
        [
            ("Pass", "cyan"),
            ("Category", "blue"),
            ("Support", "green"),
        ],
    )

    for cap in capabilities:
        table.add_row(
            cap.get("pass_name", "unknown"),
            cap.get("category", "unknown"),
            cap.get("support", "unknown"),
        )

    c.print(table)


def render_pass_validation_contexts(
    contexts: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """
    Render pass validation contexts table.

    Args:
        contexts: List of validation context dictionaries
        console: Optional console instance
    """
    if not contexts:
        return

    c = console or CONSOLE
    table = create_table(
        "Pass Validation Contexts",
        [
            ("Pass", "cyan"),
            ("Mode", "blue"),
            ("Degraded", "yellow"),
            ("Gate Failures", "red"),
        ],
    )

    for ctx in contexts:
        table.add_row(
            ctx.get("pass_name", "unknown"),
            ctx.get("validation_mode", "unknown"),
            "Yes" if ctx.get("degraded_execution") else "No",
            str(ctx.get("gate_failure_count", 0)),
        )

    c.print(table)


def render_symbolic_sections(
    symbolic_requested: int,
    observable_match: int,
    observable_mismatch: int,
    bounded_only: int,
    without_coverage: int,
    *,
    console: Console | None = None,
) -> None:
    """
    Render symbolic validation summary.

    Args:
        symbolic_requested: Total symbolic regions checked
        observable_match: Observable match count
        observable_mismatch: Observable mismatch count
        bounded_only: Bounded only count
        without_coverage: Without coverage count
        console: Optional console instance
    """
    if symbolic_requested == 0:
        return

    c = console or CONSOLE
    table = create_table(
        "Symbolic Validation Summary",
        [
            ("Metric", "cyan"),
            ("Count", "green"),
        ],
    )

    table.add_row("Symbolic Regions Checked", str(symbolic_requested))
    table.add_row("Observable Match", str(observable_match))
    table.add_row("Observable Mismatch", str(observable_mismatch))
    table.add_row("Bounded Only", str(bounded_only))
    table.add_row("Without Coverage", str(without_coverage))

    c.print(table)


def render_gate_sections(
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """
    Render gate failure summary.

    Args:
        gate_failure_summary: Gate failure summary dict
        gate_failure_priority: Priority ordered gate failures
        console: Optional console instance
    """
    c = console or CONSOLE

    if not gate_failure_summary.get("require_pass_severity_failure_count", 0):
        c.print("[green]All gate checks passed[/green]")
        return

    table = create_table(
        "Gate Failures",
        [
            ("Pass", "cyan"),
            ("Failure Count", "red"),
            ("Strictest Severity", "yellow"),
        ],
    )

    for row in gate_failure_priority:
        table.add_row(
            row.get("pass_name", "unknown"),
            str(row.get("failure_count", 0)),
            row.get("strictest_expected_severity", "unknown"),
        )

    c.print(table)


def render_degradation_sections(
    degradation_summary: dict[str, Any],
    *,
    console: Console | None = None,
) -> None:
    """
    Render validation mode degradation summary.

    Args:
        degradation_summary: Degradation summary dict
        console: Optional console instance
    """
    c = console or CONSOLE

    if not degradation_summary.get("degraded_validation"):
        return

    table = create_table(
        "Validation Mode Degradation",
        [
            ("Role", "cyan"),
            ("Count", "yellow"),
        ],
    )

    for role, count in degradation_summary.get("roles", {}).items():
        table.add_row(role, str(count))

    c.print(table)


def render_only_mismatches_sections(
    mismatch_rows: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """
    Render only-mismatches report sections.

    Args:
        mismatch_rows: List of mismatch row dictionaries
        console: Optional console instance
    """
    if not mismatch_rows:
        return

    c = console or CONSOLE
    table = create_table(
        "Observable Mismatches by Pass",
        [
            ("Pass", "cyan"),
            ("Mismatch Count", "red"),
            ("Regions Checked", "blue"),
        ],
    )

    for row in mismatch_rows:
        table.add_row(
            row.get("pass_name", "unknown"),
            str(row.get("mismatch_count", 0)),
            str(row.get("region_count", 0)),
        )

    c.print(table)


def render_only_pass_sections(
    pass_name: str,
    pass_data: dict[str, Any],
    *,
    console: Console | None = None,
) -> None:
    """
    Render sections for a single pass.

    Args:
        pass_name: Name of the pass
        pass_data: Pass data dictionary
        console: Optional console instance
    """
    c = console or CONSOLE

    c.print(f"\n[bold cyan]Pass: {pass_name}[/bold cyan]")

    if pass_data.get("evidence_summary"):
        evidence = pass_data["evidence_summary"]
        table = create_table(
            "Evidence Summary",
            [
                ("Metric", "cyan"),
                ("Value", "green"),
            ],
        )
        table.add_row("Changed Regions", str(evidence.get("changed_region_count", 0)))
        table.add_row("Structural Issues", str(evidence.get("structural_issue_count", 0)))
        table.add_row(
            "Symbolic Mismatches", str(evidence.get("symbolic_binary_mismatched_regions", 0))
        )
        c.print(table)


def render_report_filter_messages(
    only_pass: str | None,
    resolved_only_pass: str | None,
    only_pass_failure: str | None,
    resolved_only_pass_failure: str | None,
    only_risky_passes: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    *,
    console: Console | None = None,
) -> None:
    """
    Render filter resolution messages.

    Args:
        only_pass: Original --only-pass argument
        resolved_only_pass: Resolved pass name
        only_pass_failure: Original --only-pass-failure argument
        resolved_only_pass_failure: Resolved pass failure name
        only_risky_passes: --only-risky-passes flag
        only_uncovered_passes: --only-uncovered-passes flag
        only_covered_passes: --only-covered-passes flag
        only_clean_passes: --only-clean-passes flag
        console: Optional console instance
    """
    c = console or CONSOLE

    if only_pass is not None and resolved_only_pass != only_pass:
        c.print(f"[bold]Pass Filter Resolution[/bold]: {only_pass} -> {resolved_only_pass}")

    if only_pass_failure is not None and resolved_only_pass_failure != only_pass_failure:
        c.print(
            f"[bold]Pass Failure Filter Resolution[/bold]: {only_pass_failure} -> {resolved_only_pass_failure}"
        )

    if only_risky_passes:
        c.print(
            "[bold]Filter[/bold]: Showing only passes with symbolic mismatches or structural issues"
        )

    if only_uncovered_passes:
        c.print(
            "[bold]Filter[/bold]: Showing only clean passes without effective symbolic coverage"
        )

    if only_covered_passes:
        c.print("[bold]Filter[/bold]: Showing only clean passes with effective symbolic coverage")

    if only_clean_passes:
        c.print(
            "[bold]Filter[/bold]: Showing only passes with no structural issues and clean symbolic evidence"
        )


def render_summary_table(
    summary: dict[str, Any],
    *,
    console: Console | None = None,
) -> None:
    """
    Render a generic summary table.

    Args:
        summary: Summary dictionary
        console: Optional console instance
    """
    c = console or CONSOLE

    table = create_table(
        "Report Summary",
        [
            ("Metric", "cyan"),
            ("Value", "green"),
        ],
    )

    for key, value in summary.items():
        if isinstance(value, dict):
            continue
        if isinstance(value, list):
            continue
        table.add_row(key.replace("_", " ").title(), str(value))

    c.print(table)


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
    """
    Render persisted gate evaluation and failure sections.

    Args:
        gate_evaluation: Gate evaluation dict
        gate_requested: Gate requested dict
        gate_results: Gate results dict
        gate_failure_summary: Gate failure summary dict
        gate_failure_priority: Priority ordered gate failures
        gate_failure_severity_priority: Severity priority ordered failures
        console: Optional console instance
    """
    c = console or CONSOLE

    if not gate_evaluation:
        return

    c.print(
        "[bold]Gate Evaluation[/bold]: "
        f"all_passed={'yes' if gate_results.get('all_passed', True) else 'no'}"
    )

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

    severity_counts = gate_failure_summary.get(
        "require_pass_severity_failures_by_expected_severity", {}
    )
    if severity_counts:
        c.print(
            "  expected_severity_counts="
            + ", ".join(f"{severity}:{count}" for severity, count in severity_counts.items())
        )

    if gate_failure_severity_priority:
        c.print(
            "  expected_severity_priority="
            + ", ".join(
                f"{row.get('severity')}:{row.get('failure_count')}"
                for row in gate_failure_severity_priority
            )
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
                f"(count={failure_count}, strictest_expected={strictest}): "
                + ", ".join(failures_list)
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
    """
    Render general report flow sections.

    Args:
        filtered_summary: Filtered summary dict
        summary: Full summary dict
        pass_results: Pass results dict
        degraded_passes: List of degraded passes
        requested_validation_mode: Requested validation mode
        effective_validation_mode: Effective validation mode
        degraded_validation: Whether validation was degraded
        validation_policy: Validation policy dict
        gate_evaluation: Gate evaluation dict
        gate_requested: Gate requested dict
        gate_results: Gate results dict
        gate_failure_summary: Gate failure summary dict
        gate_failure_priority: Priority ordered gate failures
        gate_failure_severity_priority: Severity priority ordered failures
        degradation_roles: Degradation roles dict
        resolved_only_pass: Resolved only pass filter
        console: Optional console instance
    """
    c = console or CONSOLE

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
    """
    Render only-pass sections for general report.

    Args:
        pass_name: Pass name
        summary: Summary dict
        pass_results: Pass results dict
        resolved_only_pass: Resolved only pass filter
        console: Optional console instance
    """
    c = console or CONSOLE

    if not resolved_only_pass:
        return

    c.print(f"\n[bold cyan]Single Pass Report: {pass_name}[/bold cyan]")

    pass_result = pass_results.get(pass_name, {})
    if pass_result:
        evidence = pass_result.get("evidence_summary", {})
        if evidence:
            render_only_pass_sections(pass_name, {"evidence_summary": evidence}, console=c)


def render_mismatch_summary_sections(
    mismatch_counts_by_pass: dict[str, int],
    mismatch_observables_by_pass: dict[str, list[str]],
    *,
    console: Console | None = None,
) -> None:
    """
    Render mismatch summary sections.

    Args:
        mismatch_counts_by_pass: Dict of pass name to mismatch count
        mismatch_observables_by_pass: Dict of pass name to observable list
        console: Optional console instance
    """
    c = console or CONSOLE

    if not mismatch_counts_by_pass:
        return

    table = create_table(
        "Observable Mismatches Summary",
        [
            ("Pass", "cyan"),
            ("Count", "red"),
            ("Observables", "yellow"),
        ],
    )

    for pass_name, count in sorted(mismatch_counts_by_pass.items(), key=lambda x: -x[1]):
        observables = mismatch_observables_by_pass.get(pass_name, [])[:3]
        obs_str = ", ".join(observables)
        if len(mismatch_observables_by_pass.get(pass_name, [])) > 3:
            obs_str += "..."
        table.add_row(pass_name, str(count), obs_str)

    c.print(table)


def render_validation_context_table(
    validation_contexts: list[dict[str, Any]],
    *,
    console: Console | None = None,
) -> None:
    """
    Render validation context table.

    Args:
        validation_contexts: List of validation context dicts
        console: Optional console instance
    """
    if not validation_contexts:
        return

    c = console or CONSOLE
    table = create_table(
        "Validation Context",
        [
            ("Pass", "cyan"),
            ("Mode", "blue"),
            ("Degraded", "yellow"),
        ],
    )

    for ctx in validation_contexts:
        table.add_row(
            ctx.get("pass_name", "unknown"),
            ctx.get("validation_mode", "unknown"),
            "Yes" if ctx.get("degraded_execution") else "No",
        )

    c.print(table)
