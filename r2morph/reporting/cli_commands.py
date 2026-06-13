"""CLI command handlers extracted from `r2morph.cli`."""

import json
from pathlib import Path
from typing import Any

import typer
from rich import print as rprint

from r2morph.cli_workflows import _resolve_report_pass_filter
from r2morph.reporting import SEVERITY_ORDER
from r2morph.reporting.filtered_summary_builder import _build_report_dispatch_state
from r2morph.reporting.report_context_resolver import _resolve_report_context as _resolve_report_context_impl
from r2morph.reporting.report_orchestrator import _dispatch_report_flow
from r2morph.reporting.report_resolver import _resolve_general_report_flow_state


def _resolve_min_severity(min_severity: str | None) -> tuple[str | None, int | None]:
    """Validate and normalize a minimum severity option."""
    if min_severity is None:
        return None, None
    if min_severity not in SEVERITY_ORDER:
        rprint(f"[bold red]Error:[/bold red] Invalid --min-severity: {min_severity}")
        raise typer.Exit(2)
    return min_severity, SEVERITY_ORDER[min_severity]


def handle_mutate_command(
    input_file: Path,
    output_file: Path | None,
    mutations: list[str],
    validation_mode: str,
    report_path: Path | None,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Handle the mutate command.

    Args:
        input_file: Input binary file path
        output_file: Output binary file path
        mutations: List of mutation names to apply
        validation_mode: Validation mode (off, structural, symbolic)
        report_path: Optional path to write report JSON
        **kwargs: Additional options

    Returns:
        Dict with mutation results
    """
    from r2morph.session import MorphSession

    session: Any = MorphSession(Path(str(input_file)))
    session.set_mutations(mutations)
    session.set_validation_mode(validation_mode)

    if output_file:
        session.set_output(str(output_file))

    results: dict[str, Any] = dict(session.run())

    if report_path:
        report_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    return results


def handle_report_command(
    report_file: Path,
    only_pass: str | None = None,
    only_status: str | None = None,
    only_mismatches: bool = False,
    summary_only: bool = False,
    output: Path | None = None,
    require_results: bool = False,
    min_severity: str | None = None,
    only_expected_severity: str | None = None,
    only_pass_failure: str | None = None,
    only_degraded: bool = False,
    only_failed_gates: bool = False,
    only_risky_passes: bool = False,
    only_structural_risk: bool = False,
    only_symbolic_risk: bool = False,
    only_clean_passes: bool = False,
    only_covered_passes: bool = False,
    only_uncovered_passes: bool = False,
    output_format: str = "json",
    **kwargs: Any,
) -> dict[str, Any]:
    """Handle the report command."""
    with open(report_file, encoding="utf-8") as handle:
        payload: dict[str, Any] = json.load(handle)

    resolved_only_pass = _resolve_report_pass_filter(only_pass)
    resolved_only_pass_failure = _resolve_report_pass_filter(only_pass_failure)
    _, min_severity_rank = _resolve_min_severity(min_severity)

    return_payload: dict[str, Any] = dict(payload)
    if resolved_only_pass:
        mutations = [m for m in payload.get("mutations", []) if m.get("pass_name") == resolved_only_pass]
        return_payload["mutations"] = mutations
        return_payload["filtered_summary"] = {
            "passes": [resolved_only_pass] if mutations else [],
            "mutations": len(mutations),
        }

    context = _resolve_report_context_impl(
        payload=payload,
        resolved_only_pass=resolved_only_pass,
        resolved_only_pass_failure=resolved_only_pass_failure,
        only_expected_severity=only_expected_severity,
    )
    summary = context["summary"]
    requested_validation_mode = context["requested_validation_mode"]
    effective_validation_mode = context["effective_validation_mode"]
    validation_policy = context["validation_policy"]
    gate_evaluation = context["gate_evaluation"]
    gate_failure_summary = context["gate_failure_summary"]
    gate_failure_priority = context["gate_failure_priority"]
    gate_failure_severity_priority = context["gate_failure_severity_priority"]
    failed_gates = context["failed_gates"]
    degraded_validation = context["degraded_validation"]
    degraded_passes = context["degraded_passes"]

    pass_results = payload.get("passes", {})
    general_state = _resolve_general_report_flow_state(
        payload=payload,
        summary=summary,
        pass_results=pass_results,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        degraded_passes=degraded_passes,
        failed_gates=failed_gates,
        validation_policy=validation_policy,
        gate_evaluation=gate_evaluation,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
        resolved_only_pass=resolved_only_pass,
        only_status=only_status,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
    )

    dispatch_state = _build_report_dispatch_state(
        context=context,
        general_state=general_state,
        payload=payload,
        pass_results=pass_results,
        only_pass=only_pass,
        only_pass_failure=only_pass_failure,
        only_status=only_status,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        output=output,
        summary_only=summary_only,
        require_results=require_results,
        min_severity=min_severity,
        min_severity_rank=min_severity_rank,
        only_expected_severity=only_expected_severity,
        only_mismatches=only_mismatches,
    )

    if require_results:
        filtered_mutations = return_payload.get("mutations", payload.get("mutations", []))
        if isinstance(filtered_mutations, list):
            return_payload["mutations"] = filtered_mutations
        return_payload["filtered_summary"] = dispatch_state.get("filtered_summary", {})

    if output_format.lower() == "sarif":
        from r2morph.reporting.sarif_formatter import format_as_sarif

        sarif_report = format_as_sarif(
            payload.get("mutations", []),
            payload.get("validations", []),
            payload.get("binary_path", ""),
        )
        if output:
            with open(output, "w", encoding="utf-8") as handle:
                handle.write(sarif_report.to_json())
            rprint(f"[green]SARIF report written to[/green] {output}")
        else:
            print(sarif_report.to_json())
        return return_payload

    _dispatch_report_flow(**dispatch_state)
    return return_payload


def handle_version_command() -> str:
    """
    Handle the version command.

    Returns:
        Version string
    """
    from r2morph import __version__

    return __version__


def handle_session_command(
    input_file: Path,
    session_name: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Handle session management commands.

    Args:
        input_file: Input binary file path
        session_name: Optional session name
        **kwargs: Additional options

    Returns:
        Dict with session info
    """
    from r2morph.session import MorphSession

    session: Any = MorphSession(Path(str(input_file)))
    if session_name:
        session.set_name(session_name)

    return {
        "session_id": session.session_id,
        "binary": str(input_file),
        "name": session_name,
    }


def validate_report_filters(
    only_pass: str | None,
    only_risky_passes: bool,
    only_clean_passes: bool,
    **kwargs: Any,
) -> list[str]:
    """
    Validate that report filter options are mutually exclusive.

    Args:
        only_pass: Single pass filter
        only_risky_passes: Risky pass filter
        only_clean_passes: Clean pass filter
        **kwargs: Additional filter options

    Returns:
        List of validation errors
    """
    errors = []

    active_filters = sum(
        [
            bool(only_pass),
            only_risky_passes,
            only_clean_passes,
            kwargs.get("only_failed_gates", False),
            kwargs.get("only_mismatches", False),
            kwargs.get("only_degraded", False),
        ]
    )

    if active_filters > 1:
        errors.append("Only one filter option can be active at a time")

    return errors


def resolve_validation_mode(
    requested_mode: str,
    allow_limited: bool,
    binary_path: Path,
) -> tuple[str, str, dict[str, Any]]:
    """
    Resolve the validation mode based on capabilities and options.

    Args:
        requested_mode: Requested validation mode
        allow_limited: Whether limited mode is acceptable
        binary_path: Path to binary

    Returns:
        Tuple of (effective_mode, degradation_reason, policy)
    """
    from r2morph.core import Binary

    degradation_reason: str | None = None
    policy: dict[str, Any] = {}

    if requested_mode == "off":
        return "off", "", policy

    if requested_mode == "structural":
        return "structural", "", policy

    if requested_mode == "symbolic":
        try:
            with Binary(binary_path) as binary:
                binary.analyze("aaa")
                return "symbolic", "", policy
        except Exception as e:
            if allow_limited:
                degradation_reason = f"symbolic_not_available: {e}"
                return "structural", degradation_reason, {"limited_passes": [], "degraded": True}
            else:
                raise

    return requested_mode, "", policy


__all__ = [
    "handle_mutate_command",
    "handle_report_command",
    "handle_version_command",
    "handle_session_command",
    "validate_report_filters",
    "resolve_validation_mode",
]
