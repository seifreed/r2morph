"""Checkpoint helpers for parallel mutation execution."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from r2morph.core.parallel_planner import PassResult, PassStatus


def save_checkpoint(binary_path: Path, checkpoint_dir: Path, pass_name: str, logger: Any) -> Path:
    """Save a checkpoint of the current binary state."""
    checkpoint_path = checkpoint_dir / f"checkpoint_{pass_name}.bin"
    try:
        shutil.copy2(binary_path, checkpoint_path)
        logger.debug(f"Saved checkpoint: {checkpoint_path}")
        return checkpoint_path
    except Exception as e:
        logger.warning(f"Failed to save checkpoint: {e}")
        return Path("")


def has_failures(results: dict[str, PassResult]) -> bool:
    """Check if any pass has failed."""
    return any(r.status == PassStatus.FAILED for r in results.values())


def rollback_checkpoint(binary_path: Path, checkpoint_path: Path, logger: Any) -> bool:
    """Restore a checkpoint to the binary path."""
    try:
        shutil.copy2(checkpoint_path, binary_path)
        logger.info(f"Rolled back to checkpoint: {checkpoint_path}")
        return True
    except Exception as e:
        logger.error(f"Rollback failed: {e}")
        return False
