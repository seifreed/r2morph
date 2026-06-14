"""Parallel executor speedup estimation helpers."""

from __future__ import annotations

from r2morph.mutations.base import MutationPass


def estimate_parallel_speedup(
    passes: list[MutationPass],
    *,
    function_count: int,
    max_workers: int,
    chunk_size: int,
) -> float:
    """Estimate potential speedup from parallel execution."""
    enabled_count = sum(1 for p in passes if p.enabled)

    if enabled_count == 0:
        return 1.0

    chunk_count = max(1, function_count // chunk_size)
    task_count = enabled_count * chunk_count

    if task_count <= 1:
        return 1.0

    effective_workers = min(max_workers, task_count)
    overhead_factor = 1.0 + (0.1 * effective_workers)
    return float(effective_workers / overhead_factor)
