"""
CLI command handlers extracted from cli.py.

This module follows Interface Segregation Principle by separating
command handling logic from CLI entry points.
"""

import json
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()


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
    require_results: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Handle the report command.

    Args:
        report_file: Path to report JSON file
        only_pass: Optional pass name filter
        require_results: Exit with code 1 if empty results
        **kwargs: Additional options

    Returns:
        Dict with report payload
    """
    from r2morph.reporting import enforce_report_requirements

    with open(report_file, "r", encoding="utf-8") as handle:
        payload: dict[str, Any] = json.load(handle)

    if only_pass:
        mutations = [m for m in payload.get("mutations", []) if m.get("pass_name") == only_pass]
        payload["mutations"] = mutations
        payload["filtered_summary"] = {
            "passes": [only_pass] if mutations else [],
            "mutations": len(mutations),
        }

    if require_results:
        severity_rows = payload.get("summary", {}).get("symbolic_severity_by_pass", [])
        enforce_report_requirements(
            require_results=True,
            severity_rows=severity_rows,
            min_severity_rank=None,
            mutation_count=len(payload.get("mutations", [])),
            only_failed_gates=False,
            failed_gates=False,
            gate_failure_count=None,
            only_risky_passes=False,
            risky_pass_count=0,
            pass_count=len(payload.get("summary", {}).get("passes", [])),
        )

    return payload


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
