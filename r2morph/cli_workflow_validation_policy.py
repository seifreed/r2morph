"""Pure policy helpers for CLI workflow validation mode resolution."""

from __future__ import annotations

from typing import Any

from r2morph.cli_workflow_selection import limited_symbolic_passes
from r2morph.core.config import EngineConfig


def build_validation_mode_policy(
    *,
    requested_mode: str,
    mutations: list[str],
    config: EngineConfig,
    seed: int | None,
    allow_limited_symbolic: bool,
    limited_symbolic_policy: str,
) -> dict[str, Any]:
    """Resolve the effective mode and policy metadata without side effects."""
    if requested_mode != "symbolic":
        return {
            "effective_mode": requested_mode,
            "policy": None,
            "reason": None,
            "limited_passes": [],
        }

    limited = limited_symbolic_passes(mutations, config, seed=seed)
    if not limited:
        return {
            "effective_mode": requested_mode,
            "policy": None,
            "reason": None,
            "limited_passes": [],
        }

    if allow_limited_symbolic:
        return {
            "effective_mode": requested_mode,
            "policy": "allow",
            "reason": "explicit-override",
            "limited_passes": limited,
        }

    if limited_symbolic_policy == "degrade-runtime":
        return {
            "effective_mode": "runtime",
            "policy": limited_symbolic_policy,
            "reason": "limited-symbolic-support",
            "limited_passes": limited,
        }

    if limited_symbolic_policy == "degrade-structural":
        return {
            "effective_mode": "structural",
            "policy": limited_symbolic_policy,
            "reason": "limited-symbolic-support",
            "limited_passes": limited,
        }

    return {
        "effective_mode": requested_mode,
        "policy": None,
        "reason": None,
        "limited_passes": limited,
    }

