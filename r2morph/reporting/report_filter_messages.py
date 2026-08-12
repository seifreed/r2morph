"""Build user-facing report filter status messages."""

from __future__ import annotations

from r2morph.reporting.report_context import FilterFlags, SeverityFilter


def build_report_filter_messages(
    filters: FilterFlags,
    severity: SeverityFilter,
) -> list[str]:
    """Return compact filter-resolution/status messages."""
    messages: list[str] = []

    if filters.only_pass is not None and severity.resolved_only_pass != filters.only_pass:
        messages.append(f"[bold]Pass Filter Resolution[/bold]: {filters.only_pass} -> {severity.resolved_only_pass}")
    if filters.only_pass_failure is not None and severity.resolved_only_pass_failure != filters.only_pass_failure:
        messages.append(
            "[bold]Pass Failure Filter Resolution[/bold]: "
            f"{filters.only_pass_failure} -> {severity.resolved_only_pass_failure}"
        )
    pass_classes = filters.pass_classes
    selected_risk_pass_names = severity.selected_risk_pass_names
    if pass_classes.only_risky_passes:
        messages.append(f"[bold]Risky Pass Filter[/bold]: {len(selected_risk_pass_names)} risky pass(es) detected")
    if pass_classes.only_uncovered_passes:
        messages.append(
            f"[bold]Uncovered Pass Filter[/bold]: {len(selected_risk_pass_names)} uncovered pass(es) detected"
        )
    if pass_classes.only_covered_passes:
        messages.append(f"[bold]Covered Pass Filter[/bold]: {len(selected_risk_pass_names)} covered pass(es) detected")
    if pass_classes.only_clean_passes:
        messages.append(f"[bold]Clean Pass Filter[/bold]: {len(selected_risk_pass_names)} clean pass(es) detected")
    if pass_classes.only_structural_risk:
        messages.append(
            f"[bold]Structural Risk Filter[/bold]: {len(selected_risk_pass_names)} structural-risk pass(es) detected"
        )
    if pass_classes.only_symbolic_risk:
        messages.append(
            f"[bold]Symbolic Risk Filter[/bold]: {len(selected_risk_pass_names)} symbolic-risk pass(es) detected"
        )

    return messages
