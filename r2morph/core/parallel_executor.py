"""
Parallel mutation execution engine.

Provides parallel execution of mutations across independent functions
to improve performance on multi-core systems.
"""

import logging
import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from typing import Any

from r2morph.core.parallel_executor_models import (  # noqa: F401
    MutationResult,
    MutationTask,
    ResolutionStrategy,
    TaskStatus,
)
from r2morph.core.parallel_executor_task_helpers import (
    build_failed_mutation_result,
    build_mutation_result,
    create_tasks_from_call_graph,
)
from r2morph.core.parallel_result_merger import ResultMerger
from r2morph.core.parallel_work_queue import WorkQueue

logger = logging.getLogger(__name__)


class ParallelMutator:
    """
    Parallel mutation execution engine.

    Executes mutations across multiple functions in parallel
    using process pools for CPU-bound work.
    """

    def __init__(self, max_workers: int | None = None, use_threads: bool = False) -> None:
        """
        Initialize parallel mutator.

        Args:
            max_workers: Maximum number of workers (default: CPU count)
            use_threads: Use threads instead of processes
        """
        self.max_workers = max_workers or multiprocessing.cpu_count()
        self.use_threads = use_threads
        self._work_queue = WorkQueue()
        self._result_merger = ResultMerger()
        self._progress_callback: Any = None

    def set_progress_callback(self, callback: Any) -> None:
        """
        Set callback for progress updates.

        Args:
            callback: Function to call with (completed, total, current_task)
        """
        self._progress_callback = callback

    def create_tasks_from_call_graph(
        self,
        functions: list[dict[str, Any]],
        call_graph: dict[int, list[int]] | None = None,
    ) -> list[int]:
        """
        Create mutation tasks with dependency ordering from call graph.

        Args:
            functions: List of function info dicts
            call_graph: Dict mapping function address to list of call targets

        Returns:
            List of task IDs
        """
        return create_tasks_from_call_graph(self._work_queue, functions, call_graph)

    def execute_parallel(
        self,
        mutation_func: Any,
        binary_path: str,
        tasks: list[int] | None = None,
    ) -> dict[str, Any]:
        """
        Execute mutations in parallel.

        Args:
            mutation_func: Function to apply mutations (binary_path, function_address) -> result
            binary_path: Path to binary
            tasks: Specific task IDs to execute (None = all pending)

        Returns:
            Dictionary with execution results
        """
        start_time = time.time()

        task_ids = tasks or list(self._work_queue._tasks.keys())
        results: list[MutationResult] = []
        completed = 0
        total = len(task_ids)

        executor_cls = ThreadPoolExecutor if self.use_threads else ProcessPoolExecutor

        with executor_cls(max_workers=self.max_workers) as executor:
            futures = {}
            running_tasks: dict[Any, MutationTask] = {}

            while completed < total:
                ready_tasks = self._work_queue.get_ready_tasks(max_tasks=self.max_workers)

                for task in ready_tasks:
                    if tasks and task.task_id not in tasks:
                        continue

                    future = executor.submit(
                        mutation_func,
                        binary_path,
                        task.function_address,
                    )
                    futures[future] = task.task_id
                    running_tasks[task.task_id] = task
                    self._work_queue.mark_running(task.task_id)

                if not futures:
                    break

                done_futures = []
                for future in as_completed(futures):
                    task_id = futures[future]
                    task = running_tasks[task_id]

                    try:
                        result_data = future.result()
                        result = build_mutation_result(task_id, task, result_data)

                        self._work_queue.mark_completed(task_id, result)
                        self._result_merger.add_result(result)
                        results.append(result)

                    except Exception as e:
                        logger.error(f"Task {task_id} failed: {e}")
                        self._work_queue.mark_failed(task_id, str(e))
                        result = build_failed_mutation_result(task_id, task, e)
                        results.append(result)

                    completed += 1
                    done_futures.append(future)

                    if self._progress_callback:
                        self._progress_callback(completed, total, task)

                for future in done_futures:
                    del futures[future]

        total_time = time.time() - start_time

        merged = self._result_merger.merge(None, results)
        merged["parallel_time"] = total_time
        merged["workers"] = self.max_workers

        return merged

    def get_statistics(self) -> dict[str, Any]:
        """Get execution statistics."""
        return {
            "pending_tasks": self._work_queue.get_pending_count(),
            "running_tasks": self._work_queue.get_running_count(),
            "completed_tasks": self._work_queue.get_completed_count(),
            "failed_tasks": self._work_queue.get_failed_count(),
            "workers": self.max_workers,
        }

    def clear(self) -> None:
        """Clear all state."""
        self._work_queue.clear()
        self._result_merger.clear()


def create_parallel_mutator(
    max_workers: int | None = None,
    use_threads: bool = False,
) -> ParallelMutator:
    """
    Create a parallel mutator instance.

    Args:
        max_workers: Maximum number of workers
        use_threads: Use threads instead of processes

    Returns:
        ParallelMutator instance
    """
    return ParallelMutator(max_workers=max_workers, use_threads=use_threads)
