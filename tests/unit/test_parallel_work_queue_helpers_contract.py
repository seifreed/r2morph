from r2morph.core.parallel_executor_models import MutationTask, TaskStatus
from r2morph.core.parallel_work_queue_helpers import (
    count_tasks_with_status,
    get_dependencies,
    is_queue_empty,
    select_ready_tasks,
)


def test_select_ready_tasks_orders_by_priority() -> None:
    tasks = {
        1: MutationTask(task_id=1, function_address=0x1000, priority=1),
        2: MutationTask(task_id=2, function_address=0x2000, priority=3),
    }

    ready = select_ready_tasks(tasks, completed=set())

    assert [task.task_id for task in ready] == [2, 1]


def test_queue_helpers_count_and_dependency_queries() -> None:
    tasks = {
        1: MutationTask(task_id=1, function_address=0x1000, dependencies=[3], status=TaskStatus.COMPLETED),
        2: MutationTask(task_id=2, function_address=0x2000, status=TaskStatus.PENDING),
    }

    assert count_tasks_with_status(tasks, TaskStatus.COMPLETED) == 1
    assert count_tasks_with_status(tasks, TaskStatus.PENDING) == 1
    assert get_dependencies(tasks, 1) == [3]
    assert get_dependencies(tasks, 99) == []
    assert not is_queue_empty(tasks, running={2})
