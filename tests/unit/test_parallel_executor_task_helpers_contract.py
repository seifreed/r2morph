"""Contract tests for parallel executor task helpers."""

from __future__ import annotations

from r2morph.core.parallel_executor_models import MutationResult, MutationTask, TaskStatus
from r2morph.core.parallel_executor_task_helpers import (
    build_failed_mutation_result,
    build_mutation_result,
    create_tasks_from_call_graph,
)
from r2morph.core.parallel_work_queue import WorkQueue
from tests.utils.assertions import expect

_EXPECTED_FAILURE_FUNCTION_ADDRESS_16384 = 0x4000
_EXPECTED_FAILURE_TASK_ID_7 = 7
_EXPECTED_QUEUE_TASKS_2_PRIORITY_2 = 2
_EXPECTED_SUCCESS_BYTES_MODIFIED_3 = 3
_EXPECTED_SUCCESS_EXECUTION_TIME_0_25 = 0.25
_EXPECTED_SUCCESS_TASK_ID_7 = 7


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

    expect(task_ids == [0, 1, 2])
    expect(queue._tasks[1].dependencies == [0])
    expect(queue._tasks[2].dependencies == [0, 1])
    expect(queue._tasks[2].priority == _EXPECTED_QUEUE_TASKS_2_PRIORITY_2)

    queue.mark_completed(
        0,
        MutationResult(task_id=0, function_address=0x1000, function_name="alpha", success=True),
    )
    expect(queue.get_ready_tasks()[0].task_id == 1)


def test_result_helpers_build_success_and_failure_records() -> None:
    task = MutationTask(task_id=7, function_address=0x4000, function_name="delta")

    success = build_mutation_result(
        7,
        task,
        {"success": False, "mutations": [{"type": "nop"}], "bytes_modified": 3, "execution_time": 0.25},
    )
    failure = build_failed_mutation_result(7, task, RuntimeError("boom"))

    expect(success.task_id == _EXPECTED_SUCCESS_TASK_ID_7)
    expect(not (success.success is not False))
    expect(success.mutations_applied == [{"type": "nop"}])
    expect(success.bytes_modified == _EXPECTED_SUCCESS_BYTES_MODIFIED_3)
    expect(success.execution_time == _EXPECTED_SUCCESS_EXECUTION_TIME_0_25)

    expect(failure.task_id == _EXPECTED_FAILURE_TASK_ID_7)
    expect(not (failure.success is not False))
    expect(failure.error == "boom")
    expect(failure.function_name == "delta")
    expect(failure.function_address == _EXPECTED_FAILURE_FUNCTION_ADDRESS_16384)
    expect(TaskStatus.PENDING.value == "pending")
