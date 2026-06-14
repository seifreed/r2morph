"""Rollback helpers for parallel mutation execution."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from r2morph.core.parallel_checkpointing import rollback_checkpoint
from r2morph.core.parallel_planner import PassResult, PassStatus


def rollback_pass_checkpoint(
    *,
    binary_path: Path,
    result: PassResult | None,
    logger: Any,
) -> bool:
    """Rollback a pass to its checkpoint if one exists."""
    if not result or not result.checkpoint_path:
        logger.warning("No checkpoint for pass: rollback unavailable")
        return False

    if rollback_checkpoint(binary_path, result.checkpoint_path, logger):
        result.status = PassStatus.ROLLED_BACK
        return True
    return False
