"""Per-pass execution helpers for parallel mutation execution."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary
from r2morph.core.parallel_checkpointing import save_checkpoint
from r2morph.core.parallel_planner import PassResult, PassStatus
from r2morph.protocols import MutationPassProtocol


def execute_checkpointed_pass(
    *,
    binary: Binary,
    pass_obj: MutationPassProtocol,
    checkpoint_dir: Path,
    use_checkpoints: bool,
    file_lock: Any | None,
    use_file_lock: bool,
    binary_mutation_lock: Any,
    progress_callback: Callable[[str, float], None] | None,
    logger: Any,
) -> PassResult:
    """Execute a single mutation pass with checkpointing and optional file locking."""
    pass_name = pass_obj.name
    start_time = time.time()

    try:
        if progress_callback:
            progress_callback(pass_name, 0.0)

        logger.debug(f"Executing pass: {pass_name}")

        with binary_mutation_lock:
            checkpoint_path = save_checkpoint(binary.path, checkpoint_dir, pass_name, logger) if use_checkpoints else None

            if file_lock and use_file_lock:
                acquired = file_lock.acquire()
                if not acquired:
                    logger.error(f"Failed to acquire file lock for pass {pass_name}")
                    return PassResult(
                        pass_name=pass_name,
                        status=PassStatus.FAILED,
                        error="Failed to acquire file lock",
                        duration_seconds=time.time() - start_time,
                    )

            try:
                result = pass_obj.apply(binary)
            finally:
                if file_lock and file_lock.is_locked():
                    file_lock.release()

        duration = time.time() - start_time
        mutations_applied = result.get("mutations_applied", 0) if result else 0

        if progress_callback:
            progress_callback(pass_name, 1.0)

        return PassResult(
            pass_name=pass_name,
            status=PassStatus.COMPLETED,
            result=result,
            duration_seconds=duration,
            mutations_applied=mutations_applied,
            checkpoint_path=checkpoint_path,
        )

    except Exception as e:
        logger.error(f"Pass {pass_name} failed: {e}")
        duration = time.time() - start_time

        if file_lock and file_lock.is_locked():
            file_lock.release()

        return PassResult(
            pass_name=pass_name,
            status=PassStatus.FAILED,
            error=str(e),
            duration_seconds=duration,
        )
