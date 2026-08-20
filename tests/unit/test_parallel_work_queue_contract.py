"""Contract tests for parallel work queue helpers."""

from __future__ import annotations

from r2morph.core.parallel_executor_models import MutationResult
from r2morph.core.parallel_work_queue import WorkQueue
from tests.utils.assertions import expect

_EXPECTED_READY_0_FUNCTION_ADDRESS_4096 = 0x1000


def test_work_queue_tracks_task_lifecycle() -> None:
    queue = WorkQueue()

    task_id = queue.add_task(function_address=0x1000, function_name="func", priority=2)
    expect(task_id == 0)
    expect(queue.get_pending_count() == 1)

    ready = queue.get_ready_tasks()
    expect(len(ready) == 1)
    expect(ready[0].function_address == _EXPECTED_READY_0_FUNCTION_ADDRESS_4096)

    queue.mark_running(task_id)
    expect(queue.get_running_count() == 1)

    result = MutationResult(task_id=task_id, function_address=0x1000, function_name="func", success=True)
    queue.mark_completed(task_id, result)

    expect(queue.get_completed_count() == 1)
    expect(queue.get_pending_count() == 0)
    expect(queue.get_running_count() == 0)
