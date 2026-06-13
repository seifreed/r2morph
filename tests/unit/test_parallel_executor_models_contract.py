"""Contract tests for parallel executor models."""

from __future__ import annotations

from r2morph.core.parallel_executor_models import (
    MutationResult,
    MutationTask,
    ResolutionStrategy,
    TaskStatus,
)


def test_mutation_task_is_ready_checks_dependencies() -> None:
    task = MutationTask(task_id=1, function_address=0x401000, dependencies=[2, 3])

    assert task.is_ready({2, 3}) is True
    assert task.is_ready({2}) is False


def test_mutation_result_to_dict_serializes_addresses() -> None:
    result = MutationResult(
        task_id=7,
        function_address=0x401000,
        function_name="demo",
        success=True,
    )

    payload = result.to_dict()

    assert payload["function_address"] == "0x401000"
    assert payload["success"] is True


def test_task_and_resolution_statuses_are_stable() -> None:
    assert TaskStatus.PENDING.value == "pending"
    assert ResolutionStrategy.MERGE.value == "merge"
