"""
Parallel mutation execution engine.

Provides parallel execution of mutations across independent functions
to improve performance on multi-core systems.
"""

import logging
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import time

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Status of a mutation task."""

    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ResolutionStrategy(Enum):
    """Strategy for conflict resolution."""

    SKIP = "skip"
    REORDER = "reorder"
    MERGE = "merge"
    ABORT = "abort"


@dataclass
class MutationTask:
    """Represents a mutation task for parallel execution."""

    task_id: int
    function_address: int
    function_name: str = ""
    passes: list[str] = field(default_factory=list)
    dependencies: list[int] = field(default_factory=list)
    priority: int = 0
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: str | None = None
    execution_time: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.task_id)

    def is_ready(self, completed: set[int]) -> bool:
        """Check if task is ready to run."""
        return all(dep in completed for dep in self.dependencies)


@dataclass
class MutationResult:
    """Result of a mutation task."""

    task_id: int
    function_address: int
    function_name: str
    success: bool
    mutations_applied: list[dict[str, Any]] = field(default_factory=list)
    bytes_modified: int = 0
    execution_time: float = 0.0
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "task_id": self.task_id,
            "function_address": f"0x{self.function_address:x}",
            "function_name": self.function_name,
            "success": self.success,
            "mutations_applied": self.mutations_applied,
            "bytes_modified": self.bytes_modified,
            "execution_time": self.execution_time,
            "error": self.error,
            "metadata": self.metadata,
        }


class WorkQueue:
    """
    Work queue for distributing mutation tasks.

    Handles task dependencies and prioritization.
    """

    def __init__(self):
        self._tasks: dict[int, MutationTask] = {}
        self._completed: set[int] = set()
        self._running: set[int] = set()
        self._task_counter = 0

    def add_task(
        self,
        function_address: int,
        function_name: str = "",
        passes: list[str] | None = None,
        dependencies: list[int] | None = None,
        priority: int = 0,
    ) -> int:
        """
        Add a task to the queue.

        Args:
            function_address: Function address to mutate
            function_name: Function name
            passes: List of mutation pass names
            dependencies: List of task IDs that must complete first
            priority: Task priority (higher = more important)

        Returns:
            Task ID
        """
        task_id = self._task_counter
        self._task_counter += 1

        task = MutationTask(
            task_id=task_id,
            function_address=function_address,
            function_name=function_name,
            passes=passes or [],
            dependencies=dependencies or [],
            priority=priority,
        )

        self._tasks[task_id] = task
        return task_id

    def get_ready_tasks(self, max_tasks: int = 0) -> list[MutationTask]:
        """
        Get tasks that are ready to run.

        Args:
            max_tasks: Maximum number of tasks to return (0 = all)

        Returns:
            List of ready tasks sorted by priority
        """
        ready = []

        for task_id, task in self._tasks.items():
            if task.status == TaskStatus.PENDING and task.is_ready(self._completed):
                ready.append(task)

        ready.sort(key=lambda t: t.priority, reverse=True)

        if max_tasks > 0:
            ready = ready[:max_tasks]

        return ready

    def mark_running(self, task_id: int) -> None:
        """Mark a task as running."""
        if task_id in self._tasks:
            self._tasks[task_id].status = TaskStatus.RUNNING
            self._running.add(task_id)

    def mark_completed(self, task_id: int, result: MutationResult) -> None:
        """Mark a task as completed."""
        if task_id in self._tasks:
            self._tasks[task_id].status = TaskStatus.COMPLETED
            self._tasks[task_id].result = result
            self._completed.add(task_id)
            self._running.discard(task_id)

    def mark_failed(self, task_id: int, error: str) -> None:
        """Mark a task as failed."""
        if task_id in self._tasks:
            self._tasks[task_id].status = TaskStatus.FAILED
            self._tasks[task_id].error = error
            self._running.discard(task_id)

    def mark_skipped(self, task_id: int) -> None:
        """Mark a task as skipped."""
        if task_id in self._tasks:
            self._tasks[task_id].status = TaskStatus.SKIPPED

    def get_dependencies(self, task_id: int) -> list[int]:
        """Get dependencies for a task."""
        return self._tasks.get(task_id, MutationTask(task_id=task_id, function_address=0)).dependencies

    def get_pending_count(self) -> int:
        """Get count of pending tasks."""
        return sum(1 for t in self._tasks.values() if t.status == TaskStatus.PENDING)

    def get_running_count(self) -> int:
        """Get count of running tasks."""
        return len(self._running)

    def get_completed_count(self) -> int:
        """Get count of completed tasks."""
        return len(self._completed)

    def get_failed_count(self) -> int:
        """Get count of failed tasks."""
        return sum(1 for t in self._tasks.values() if t.status == TaskStatus.FAILED)

    def is_empty(self) -> bool:
        """Check if queue is empty (no pending or running tasks)."""
        return self.get_pending_count() == 0 and self.get_running_count() == 0

    def clear(self) -> None:
        """Clear all tasks."""
        self._tasks.clear()
        self._completed.clear()
        self._running.clear()
        self._task_counter = 0


class ResultMerger:
    """
    Merges mutation results from parallel execution.
    """

    def __init__(self):
        self._results: list[MutationResult] = []
        self._conflicts: list[dict[str, Any]] = []

    def add_result(self, result: MutationResult) -> None:
        """Add a mutation result."""
        self._results.append(result)

    def merge(self, binary: Binary, results: list[MutationResult] | None = None) -> dict[str, Any]:
        """
        Merge mutation results.

        Args:
            binary: Original binary
            results: Results to merge (or use stored results)

        Returns:
            Dictionary with merged results
        """
        results = results or self._results

        merged = {
            "total_functions": len(results),
            "successful": sum(1 for r in results if r.success),
            "failed": sum(1 for r in results if not r.success),
            "total_mutations": sum(len(r.mutations_applied) for r in results),
            "total_bytes_modified": sum(r.bytes_modified for r in results),
            "total_time": sum(r.execution_time for r in results),
            "results": [r.to_dict() for r in results],
            "conflicts": self._conflicts,
        }

        return merged

    def detect_conflicts(self, results: list[MutationResult]) -> list[dict[str, Any]]:
        """
        Detect conflicts between mutation results.

        Args:
            results: List of mutation results

        Returns:
            List of conflicts
        """
        conflicts = []
        regions_by_func: dict[int, list[dict]] = {}

        for result in results:
            if not result.success:
                continue

            for mutation in result.mutations_applied:
                addr = mutation.get("address", 0)
                size = mutation.get("size", 0)

                if result.function_address not in regions_by_func:
                    regions_by_func[result.function_address] = []

                regions_by_func[result.function_address].append(
                    {
                        "start": addr,
                        "end": addr + size,
                        "mutation": mutation,
                        "task_id": result.task_id,
                    }
                )

        for func_addr, regions in regions_by_func.items():
            for i, r1 in enumerate(regions):
                for r2 in regions[i + 1 :]:
                    if r1["start"] < r2["end"] and r2["start"] < r1["end"]:
                        conflicts.append(
                            {
                                "function": f"0x{func_addr:x}",
                                "region1": (r1["start"], r1["end"]),
                                "region2": (r2["start"], r2["end"]),
                                "task_ids": [r1["task_id"], r2["task_id"]],
                            }
                        )

        self._conflicts = conflicts
        return conflicts

    def resolve_conflicts(
        self,
        conflicts: list[dict[str, Any]],
        strategy: ResolutionStrategy = ResolutionStrategy.SKIP,
    ) -> list[dict[str, Any]]:
        """
        Generate resolutions for conflicts.

        Args:
            conflicts: List of conflicts
            strategy: Resolution strategy

        Returns:
            List of resolutions
        """
        resolutions = []

        for conflict in conflicts:
            resolution = {
                "conflict": conflict,
                "strategy": strategy.value,
                "description": "",
            }

            if strategy == ResolutionStrategy.SKIP:
                resolution["description"] = f"Skip conflicting mutation in {conflict['function']}"
                resolution["action"] = "skip_second"

            elif strategy == ResolutionStrategy.REORDER:
                resolution["description"] = f"Reorder mutations to avoid overlap"
                resolution["action"] = "reorder"

            elif strategy == ResolutionStrategy.MERGE:
                resolution["description"] = f"Merge mutations into single pass"
                resolution["action"] = "merge"

            else:
                resolution["description"] = f"Abort due to unresolvable conflict"
                resolution["action"] = "abort"

            resolutions.append(resolution)

        return resolutions

    def clear(self) -> None:
        """Clear stored results."""
        self._results.clear()
        self._conflicts.clear()


class ParallelMutator:
    """
    Parallel mutation execution engine.

    Executes mutations across multiple functions in parallel
    using process pools for CPU-bound work.
    """

    def __init__(self, max_workers: int | None = None, use_threads: bool = False):
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
        task_ids = []
        func_to_task: dict[int, int] = {}

        for func in functions:
            addr = func.get("offset", func.get("addr", 0))
            name = func.get("name", f"func_{addr:x}")
            passes = func.get("passes", [])

            deps = []
            if call_graph and addr in call_graph:
                for caller in call_graph:
                    if addr in call_graph[caller] and caller in func_to_task:
                        deps.append(func_to_task[caller])

            task_id = self._work_queue.add_task(
                function_address=addr,
                function_name=name,
                passes=passes,
                dependencies=deps,
                priority=len(deps),
            )

            task_ids.append(task_id)
            func_to_task[addr] = task_id

        return task_ids

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

        ExecutorClass = ThreadPoolExecutor if self.use_threads else ProcessPoolExecutor

        with ExecutorClass(max_workers=self.max_workers) as executor:
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

                        result = MutationResult(
                            task_id=task_id,
                            function_address=task.function_address,
                            function_name=task.function_name,
                            success=result_data.get("success", True),
                            mutations_applied=result_data.get("mutations", []),
                            bytes_modified=result_data.get("bytes_modified", 0),
                            execution_time=result_data.get("execution_time", 0.0),
                        )

                        self._work_queue.mark_completed(task_id, result)
                        self._result_merger.add_result(result)
                        results.append(result)

                    except Exception as e:
                        logger.error(f"Task {task_id} failed: {e}")
                        self._work_queue.mark_failed(task_id, str(e))

                        result = MutationResult(
                            task_id=task_id,
                            function_address=task.function_address,
                            function_name=task.function_name,
                            success=False,
                            error=str(e),
                        )
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
