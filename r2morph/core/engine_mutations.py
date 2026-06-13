"""Mutation helpers extracted from MorphEngine."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from r2morph.protocols import MutationPassProtocol

logger = logging.getLogger(__name__)


def mutations(engine: Any) -> Sequence[MutationPassProtocol]:
    """Return the registered mutation passes."""
    return engine.pipeline.passes


def add_mutation(engine: Any, mutation: MutationPassProtocol | str) -> Any:
    """Add a mutation pass to the pipeline."""
    if isinstance(mutation, str):
        mutation = resolve_mutation_pass(mutation)
    if engine._memory_efficient_mode:
        mutation.configure_for_memory_constraints(0.4)

    engine.pipeline.add_pass(mutation)
    logger.debug(f"Added mutation: {mutation.__class__.__name__}")
    return engine


def resolve_mutation_pass(name: str) -> MutationPassProtocol:
    """Resolve a mutation pass name to an instance."""
    from r2morph.mutations import (
        BlockReorderingPass,
        InstructionExpansionPass,
        InstructionSubstitutionPass,
        NopInsertionPass,
        RegisterSubstitutionPass,
    )

    pass_map: dict[str, type[MutationPassProtocol]] = {
        "nop": NopInsertionPass,
        "substitute": InstructionSubstitutionPass,
        "register": RegisterSubstitutionPass,
        "expand": InstructionExpansionPass,
        "block": BlockReorderingPass,
    }
    cls = pass_map.get(name)
    if cls is None:
        raise ValueError(f"Unknown mutation pass: {name!r}. Valid names: {list(pass_map)}")
    return cls()


def remove_mutation(engine: Any, mutation_name: str) -> Any:
    """Remove a mutation pass from the pipeline by name."""
    engine.pipeline.remove_pass_by_name(mutation_name)
    logger.debug(f"Removed mutation: {mutation_name}")
    return engine
