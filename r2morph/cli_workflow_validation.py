"""Validation and severity resolution helpers for CLI workflows."""

from __future__ import annotations

from typing import Any

import typer
from rich import print as rprint

from r2morph.cli_workflow_selection import limited_symbolic_passes
from r2morph.cli_workflow_validation_policy import build_validation_mode_policy
from r2morph.core.config import EngineConfig
from r2morph.reporting import SEVERITY_ORDER


def warn_experimental_validation_mode(validation_mode: str) -> None:
    """Warn when the user selects symbolic validation."""
    if validation_mode != "symbolic":
        return
    rprint("[yellow]Experimental validation mode selected:[/yellow] symbolic")
    rprint(
        "[yellow]This mode performs bounded symbolic prechecks and structural fallback; it does not prove general semantic equivalence.[/yellow]"
    )


def resolve_min_severity(min_severity: str | None) -> tuple[str | None, int | None]:
    """Validate and normalize a minimum severity option."""
    if min_severity is None:
        return None, None
    if min_severity not in SEVERITY_ORDER:
        rprint(f"[bold red]Error:[/bold red] Invalid --min-severity: {min_severity}")
        raise typer.Exit(2)
    return min_severity, SEVERITY_ORDER[min_severity]


def resolve_pass_severity_requirements(
    requirements: list[str] | None,
    *,
    alias_map: dict[str, str] | None = None,
) -> list[tuple[str, str, int]]:
    """Parse repeated PassName=severity requirements for mutate gating."""
    resolved: list[tuple[str, str, int]] = []
    aliases = {key.strip(): value for key, value in (alias_map or {}).items()}
    valid_pass_names = set(aliases.values())
    for item in requirements or []:
        if "=" not in item:
            rprint(f"[bold red]Error:[/bold red] Invalid --require-pass-severity: {item}. Expected PassName=severity")
            raise typer.Exit(2)
        pass_name, severity = item.split("=", 1)
        pass_name = pass_name.strip()
        severity = severity.strip()
        pass_name = aliases.get(pass_name, pass_name)
        if not pass_name or severity not in SEVERITY_ORDER or (valid_pass_names and pass_name not in valid_pass_names):
            rprint(
                "[bold red]Error:[/bold red] "
                f"Invalid --require-pass-severity: {item}. "
                "Expected PassName=severity with severity in "
                "mismatch, without-coverage, bounded-only, clean, not-requested"
            )
            raise typer.Exit(2)
        resolved.append((pass_name, severity, SEVERITY_ORDER[severity]))
    return resolved


def resolve_validation_mode(
    *,
    requested_mode: str,
    mutations: list[str],
    config: EngineConfig,
    seed: int | None,
    allow_limited_symbolic: bool,
    limited_symbolic_policy: str,
) -> tuple[str, dict[str, Any] | None]:
    """Resolve requested vs effective validation mode for limited symbolic passes."""
    if requested_mode != "symbolic":
        return requested_mode, None

    policy = build_validation_mode_policy(
        requested_mode=requested_mode,
        mutations=mutations,
        config=config,
        seed=seed,
        allow_limited_symbolic=allow_limited_symbolic,
        limited_symbolic_policy=limited_symbolic_policy,
    )
    limited = policy["limited_passes"]
    if not limited:
        return requested_mode, None

    if policy["policy"] == "allow":
        names = ", ".join(item["pass_name"] for item in limited)
        rprint(f"[yellow]Limited symbolic coverage explicitly allowed for:[/yellow] {names}")
        for item in limited:
            rprint(f"[yellow]- {item['pass_name']}: symbolic confidence={item['confidence']}[/yellow]")
        return requested_mode, {
            "requested_mode": requested_mode,
            "effective_mode": requested_mode,
            "policy": "allow",
            "reason": "explicit-override",
            "limited_passes": limited,
        }

    if policy["effective_mode"] == "runtime":
        names = ", ".join(item["pass_name"] for item in limited)
        rprint(f"[yellow]Limited symbolic support detected for:[/yellow] {names}")
        rprint("[yellow]Degrading validation mode from symbolic to runtime.[/yellow]")
        return "runtime", {
            "requested_mode": requested_mode,
            "effective_mode": "runtime",
            "policy": policy["policy"],
            "reason": policy["reason"],
            "limited_passes": limited,
        }

    if policy["effective_mode"] == "structural":
        names = ", ".join(item["pass_name"] for item in limited)
        rprint(f"[yellow]Limited symbolic support detected for:[/yellow] {names}")
        rprint("[yellow]Degrading validation mode from symbolic to structural.[/yellow]")
        return "structural", {
            "requested_mode": requested_mode,
            "effective_mode": "structural",
            "policy": policy["policy"],
            "reason": policy["reason"],
            "limited_passes": limited,
        }

    _warn_or_block_limited_symbolic(
        mutations,
        config,
        seed=seed,
        allow_limited_symbolic=allow_limited_symbolic,
    )
    return requested_mode, None


def _warn_or_block_limited_symbolic(
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None,
    allow_limited_symbolic: bool,
) -> None:
    """Block symbolic mode for passes that declare limited symbolic support unless explicitly allowed."""
    limited = limited_symbolic_passes(mutations, config, seed=seed)
    if not limited:
        return

    names = ", ".join(item["pass_name"] for item in limited)
    if not allow_limited_symbolic:
        rprint(f"[bold red]Error:[/bold red] symbolic validation is marked limited for: {names}")
        rprint("[yellow]Use structural/runtime, or pass --allow-limited-symbolic to continue anyway.[/yellow]")
        raise typer.Exit(2)

    rprint(f"[yellow]Limited symbolic coverage explicitly allowed for:[/yellow] {names}")
    for item in limited:
        rprint(f"[yellow]- {item['pass_name']}: symbolic confidence={item['confidence']}[/yellow]")
