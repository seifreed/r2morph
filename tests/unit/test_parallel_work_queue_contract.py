"""Contract tests for parallel work queue helpers."""

from __future__ import annotations

from r2morph.core.parallel_executor_models import MutationResult
from r2morph.core.parallel_work_queue import WorkQueue


def test_work_queue_tracks_task_lifecycle() -> None:
    queue = WorkQueue()

    task_id = queue.add_task(function_address=0x1000, function_name="func", priority=2)
    assert task_id == 0
    assert queue.get_pending_count() == 1

    ready = queue.get_ready_tasks()
    assert len(ready) == 1
    assert ready[0].function_address == 0x1000

    queue.mark_running(task_id)
    assert queue.get_running_count() == 1

    result = MutationResult(task_id=task_id, function_address=0x1000, function_name="func", success=True)
    queue.mark_completed(task_id, result)

    assert queue.get_completed_count() == 1
    assert queue.get_pending_count() == 0
    assert queue.get_running_count() == 0
