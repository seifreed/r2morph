"""Mutation application flow for MorphSession."""

from __future__ import annotations

import logging
import shutil
from typing import Any

logger = logging.getLogger(__name__)


def apply_mutation(session: Any, mutation_pass: Any, description: str = "") -> dict[str, Any]:
    """Apply a mutation pass inside a MorphSession and handle rollback on failure."""
    from r2morph.core.binary import Binary

    if session.current_binary is None:
        raise ValueError("No active binary in session")

    logger.info(f"Applying mutation: {mutation_pass.name}")

    checkpoint_before = session.checkpoint("pre_mutation", description or f"Before {mutation_pass.name}")
    mutations_before = session.mutations_count

    binary = None
    try:
        binary = Binary(session.current_binary, writable=True)
        binary.open()
        binary.analyze()
        result: dict[str, Any] = mutation_pass.apply(binary)

        mutations_applied = result.get("mutations_applied", 0)
        session.mutations_count += mutations_applied

        logger.info(f"Applied {mutations_applied} mutations (total: {session.mutations_count})")

        return result
    except Exception as exc:
        logger.error(f"Mutation failed: {mutation_pass.name}: {exc}")
        session.mutations_count = mutations_before
        rollback_ok = False
        if session.current_binary and checkpoint_before.binary_path.exists():
            try:
                shutil.copy2(checkpoint_before.binary_path, session.current_binary)
                rollback_ok = True
            except FileNotFoundError:
                logger.warning(f"Checkpoint file disappeared: {checkpoint_before.binary_path}")
            except Exception as rollback_error:
                logger.error(f"Failed to rollback: {rollback_error}")
        if rollback_ok:
            session._remove_checkpoint(checkpoint_before)
        raise
    finally:
        if binary is not None:
            try:
                binary.close()
            except Exception as close_error:
                logger.debug(f"Error closing binary: {close_error}")
