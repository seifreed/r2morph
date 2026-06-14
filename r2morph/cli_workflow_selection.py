"""Mutation pass selection helpers for CLI workflows."""

from __future__ import annotations

from typing import Any

from r2morph.core.config import EngineConfig
from r2morph.core.support import PRODUCT_SUPPORT


def build_config(aggressive: bool, force: bool) -> EngineConfig:
    config = EngineConfig.create_aggressive() if aggressive else EngineConfig.create_default()
    if force:
        config.force_different = True
        config.nop.force_different = True
        config.substitution.force_different = True
        config.register.force_different = True
        config.expansion.force_different = True
        config.block.force_different = True
    return config


def mutation_config(section: Any, seed: int | None, offset: int) -> dict[str, Any]:
    cfg: dict[str, Any] = section.to_dict()
    if seed is not None:
        cfg["seed"] = seed + offset
    return cfg


def load_mutation_pass_types() -> dict[str, type]:
    """Lazy import mutation passes so stable report/validate flows avoid extra imports."""
    from r2morph.mutations import (
        BlockReorderingPass,
        InstructionExpansionPass,
        InstructionSubstitutionPass,
        NopInsertionPass,
        RegisterSubstitutionPass,
    )

    return {
        "nop": NopInsertionPass,
        "substitute": InstructionSubstitutionPass,
        "register": RegisterSubstitutionPass,
        "expand": InstructionExpansionPass,
        "block": BlockReorderingPass,
    }


def selected_mutation_passes(
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None = None,
) -> list[tuple[str, Any]]:
    """Build pass instances for the selected mutation names."""
    pass_types = load_mutation_pass_types()
    selected: list[tuple[str, Any]] = []
    offset = 0
    if "nop" in mutations:
        selected.append(("nop", pass_types["nop"](config=mutation_config(config.nop, seed, offset))))
        offset += 1
    if "substitute" in mutations:
        selected.append(
            (
                "substitute",
                pass_types["substitute"](config=mutation_config(config.substitution, seed, offset)),
            )
        )
        offset += 1
    if "register" in mutations:
        selected.append(
            (
                "register",
                pass_types["register"](config=mutation_config(config.register, seed, offset)),
            )
        )
        offset += 1
    if "expand" in mutations:
        selected.append(
            (
                "expand",
                pass_types["expand"](config=mutation_config(config.expansion, seed, offset)),
            )
        )
        offset += 1
    if "block" in mutations:
        selected.append(("block", pass_types["block"](config=mutation_config(config.block, seed, offset))))
    return selected


def mutation_pass_alias_map(
    config: EngineConfig,
    *,
    seed: int | None = None,
) -> dict[str, str]:
    """Build aliases from short mutation names to concrete pass names."""
    aliases: dict[str, str] = {}
    all_mutations = list(set(PRODUCT_SUPPORT.stable_mutations) | set(PRODUCT_SUPPORT.experimental_mutations))
    for mutation_name, mutation_pass in selected_mutation_passes(
        all_mutations,
        config,
        seed=seed,
    ):
        aliases[mutation_name] = mutation_pass.name
        aliases[mutation_pass.name] = mutation_pass.name
    return aliases


def limited_symbolic_passes(
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None,
) -> list[dict[str, str]]:
    """Return passes that declare symbolic support as limited."""
    limited = []
    for mutation_name, mutation_pass in selected_mutation_passes(mutations, config, seed=seed):
        symbolic_support = mutation_pass.get_support().validator_capabilities.get("symbolic", {})
        if symbolic_support.get("recommended") is False:
            limited.append(
                {
                    "mutation": mutation_name,
                    "pass_name": mutation_pass.name,
                    "confidence": str(symbolic_support.get("confidence", "unknown")),
                }
            )
    return limited
