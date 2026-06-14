"""Work queue helpers for parallel mutation execution."""

from __future__ import annotations

from r2morph.core.parallel_executor_models import MutationResult, MutationTask, TaskStatus
from r2morph.core.parallel_work_queue_helpers import (
    count_tasks_with_status,
    get_dependencies,
    is_queue_empty,
    select_ready_tasks,
)


class WorkQueue:
    """Work queue for distributing mutation tasks."""

    def __init__(self) -> None:
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
        """Add a task to the queue."""
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
        """Get tasks that are ready to run."""
        return select_ready_tasks(self._tasks, self._completed, max_tasks)

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
        return get_dependencies(self._tasks, task_id)

    def get_pending_count(self) -> int:
        """Get count of pending tasks."""
        return count_tasks_with_status(self._tasks, TaskStatus.PENDING)

    def get_running_count(self) -> int:
        """Get count of running tasks."""
        return len(self._running)

    def get_completed_count(self) -> int:
        """Get count of completed tasks."""
        return count_tasks_with_status(self._tasks, TaskStatus.COMPLETED)

    def get_failed_count(self) -> int:
        """Get count of failed tasks."""
        return count_tasks_with_status(self._tasks, TaskStatus.FAILED)

    def is_empty(self) -> bool:
        """Check if queue is empty (no pending or running tasks)."""
        return is_queue_empty(self._tasks, self._running)

    def clear(self) -> None:
        """Clear all tasks."""
        self._tasks.clear()
        self._completed.clear()
        self._running.clear()
        self._task_counter = 0
