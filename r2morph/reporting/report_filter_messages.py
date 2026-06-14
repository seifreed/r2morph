"""Build user-facing report filter status messages."""

from __future__ import annotations


def build_report_filter_messages(
    *,
    only_pass: str | None,
    resolved_only_pass: str | None,
    only_pass_failure: str | None,
    resolved_only_pass_failure: str | None,
    only_risky_passes: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    selected_risk_pass_names: set[str],
) -> list[str]:
    """Return compact filter-resolution/status messages."""
    messages: list[str] = []

    if only_pass is not None and resolved_only_pass != only_pass:
        messages.append(f"[bold]Pass Filter Resolution[/bold]: {only_pass} -> {resolved_only_pass}")
    if only_pass_failure is not None and resolved_only_pass_failure != only_pass_failure:
        messages.append(f"[bold]Pass Failure Filter Resolution[/bold]: {only_pass_failure} -> {resolved_only_pass_failure}")
    if only_risky_passes:
        messages.append(f"[bold]Risky Pass Filter[/bold]: {len(selected_risk_pass_names)} risky pass(es) detected")
    if only_uncovered_passes:
        messages.append(f"[bold]Uncovered Pass Filter[/bold]: {len(selected_risk_pass_names)} uncovered pass(es) detected")
    if only_covered_passes:
        messages.append(f"[bold]Covered Pass Filter[/bold]: {len(selected_risk_pass_names)} covered pass(es) detected")
    if only_clean_passes:
        messages.append(f"[bold]Clean Pass Filter[/bold]: {len(selected_risk_pass_names)} clean pass(es) detected")
    if only_structural_risk:
        messages.append(
            f"[bold]Structural Risk Filter[/bold]: {len(selected_risk_pass_names)} structural-risk pass(es) detected"
        )
    if only_symbolic_risk:
        messages.append(f"[bold]Symbolic Risk Filter[/bold]: {len(selected_risk_pass_names)} symbolic-risk pass(es) detected")

    return messages
