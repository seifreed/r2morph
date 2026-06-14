"""Work queue helpers for parallel mutation execution."""

from __future__ import annotations

from r2morph.core.parallel_executor_models import MutationResult, MutationTask, TaskStatus


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
