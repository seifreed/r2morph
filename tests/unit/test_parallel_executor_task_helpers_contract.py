"""Contract tests for parallel executor task helpers."""

from __future__ import annotations

from r2morph.core.parallel_executor_models import MutationResult, MutationTask, TaskStatus
from r2morph.core.parallel_executor_task_helpers import (
    build_failed_mutation_result,
    build_mutation_result,
    create_tasks_from_call_graph,
)
from r2morph.core.parallel_work_queue import WorkQueue


def test_create_tasks_from_call_graph_preserves_dependency_order() -> None:
    queue = WorkQueue()

    task_ids = create_tasks_from_call_graph(
        queue,
        functions=[
            {"offset": 0x1000, "name": "alpha"},
            {"offset": 0x2000, "name": "beta"},
            {"offset": 0x3000, "name": "gamma"},
        ],
        call_graph={
            0x1000: [0x2000, 0x3000],
            0x2000: [0x3000],
            0x3000: [],
        },
    )

    assert task_ids == [0, 1, 2]
    assert queue._tasks[1].dependencies == [0]
    assert queue._tasks[2].dependencies == [0, 1]
    assert queue._tasks[2].priority == 2

    queue.mark_completed(
        0,
        MutationResult(task_id=0, function_address=0x1000, function_name="alpha", success=True),
    )
    assert queue.get_ready_tasks()[0].task_id == 1


def test_result_helpers_build_success_and_failure_records() -> None:
    task = MutationTask(task_id=7, function_address=0x4000, function_name="delta")

    success = build_mutation_result(
        7,
        task,
        {"success": False, "mutations": [{"type": "nop"}], "bytes_modified": 3, "execution_time": 0.25},
    )
    failure = build_failed_mutation_result(7, task, RuntimeError("boom"))

    assert success.task_id == 7
    assert success.success is False
    assert success.mutations_applied == [{"type": "nop"}]
    assert success.bytes_modified == 3
    assert success.execution_time == 0.25

    assert failure.task_id == 7
    assert failure.success is False
    assert failure.error == "boom"
    assert failure.function_name == "delta"
    assert failure.function_address == 0x4000
    assert TaskStatus.PENDING.value == "pending"
