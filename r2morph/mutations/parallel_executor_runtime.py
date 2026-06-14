"""Runtime helpers for parallel mutation execution."""

from __future__ import annotations

import concurrent.futures
import time
from collections.abc import Callable
from typing import Any

from r2morph.mutations.base import MutationPass, MutationRecord


def execute_parallel_runs(
    passes: list[MutationPass],
    binary: Any,
    *,
    max_workers: int,
    timeout: float,
    create_tasks: Callable[[list[MutationPass], Any], list[Any]],
    execute_task: Callable[[Any, str], Any],
    stats_factory: Callable[..., Any],
    logger: Any,
) -> tuple[list[MutationRecord], Any]:
    """Execute mutation tasks in parallel and aggregate results."""
    start_time = time.perf_counter()

    functions = binary.get_functions()
    binary_path = str(binary.path)

    tasks = create_tasks(passes, functions)
    if not tasks:
        return [], stats_factory()

    all_records: list[MutationRecord] = []
    stats = stats_factory(worker_count=min(max_workers, len(tasks)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {executor.submit(execute_task, task, binary_path): task for task in tasks}

        try:
            for future in concurrent.futures.as_completed(future_to_task, timeout=timeout):
                task = future_to_task[future]

                try:
                    result = future.result()

                    if result.success:
                        stats.tasks_completed += 1
                        stats.total_mutations += result.mutations_applied
                        all_records.extend(result.records)
                    else:
                        stats.tasks_failed += 1
                        for error in result.errors:
                            logger.warning(f"Task {task.pass_name} error: {error}")

                except Exception as exc:
                    stats.tasks_failed += 1
                    logger.error(f"Task {task.pass_name} failed: {exc}")

        except concurrent.futures.TimeoutError:
            # The whole batch exceeded timeout. Count unfinished tasks as
            # failed, cancel the ones not yet started, and return partial
            # results instead of raising.
            unfinished = [future for future in future_to_task if not future.done()]
            for pending in unfinished:
                pending.cancel()
            stats.tasks_failed += len(unfinished)
            logger.error(
                f"Parallel execution timed out after {timeout}s; "
                f"{len(unfinished)} task(s) did not complete"
            )

    elapsed = time.perf_counter() - start_time
    stats.total_time = elapsed

    if stats.tasks_completed > 0:
        sequential_estimate = stats.total_time * max_workers
        stats.speedup_factor = sequential_estimate / (elapsed + 0.001)

    logger.info(
        f"Parallel execution complete: {stats.tasks_completed} tasks, "
        f"{stats.total_mutations} mutations in {elapsed:.2f}s "
        f"(speedup: {stats.speedup_factor:.2f}x)"
    )

    return all_records, stats
