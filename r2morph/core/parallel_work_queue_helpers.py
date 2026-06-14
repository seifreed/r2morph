"""Pure helpers for parallel work queue state queries."""

from __future__ import annotations

from r2morph.core.parallel_executor_models import MutationTask, TaskStatus


def select_ready_tasks(tasks: dict[int, MutationTask], completed: set[int], max_tasks: int = 0) -> list[MutationTask]:
    """Return ready tasks ordered by priority."""
    ready = [
        task
        for task in tasks.values()
        if task.status == TaskStatus.PENDING and task.is_ready(completed)
    ]
    ready.sort(key=lambda t: t.priority, reverse=True)

    if max_tasks > 0:
        ready = ready[:max_tasks]

    return ready


def count_tasks_with_status(tasks: dict[int, MutationTask], status: TaskStatus) -> int:
    """Count tasks with a given status."""
    return sum(1 for task in tasks.values() if task.status == status)


def is_queue_empty(tasks: dict[int, MutationTask], running: set[int]) -> bool:
    """Check whether the queue has no pending or running tasks."""
    return not any(task.status == TaskStatus.PENDING for task in tasks.values()) and not running


def get_dependencies(tasks: dict[int, MutationTask], task_id: int) -> list[int]:
    """Return the dependencies for a task id."""
    task = tasks.get(task_id)
    return task.dependencies if task is not None else []
