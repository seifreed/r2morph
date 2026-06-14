"""Task and result helpers for parallel mutation execution."""

from __future__ import annotations

from typing import Any

from r2morph.core.parallel_executor_models import MutationResult, MutationTask
from r2morph.core.parallel_executor_task_policies import (
    build_task_priority,
    infer_task_dependencies,
    resolve_function_address,
    resolve_function_name,
)
from r2morph.core.parallel_work_queue import WorkQueue


def create_tasks_from_call_graph(
    work_queue: WorkQueue,
    functions: list[dict[str, Any]],
    call_graph: dict[int, list[int]] | None = None,
) -> list[int]:
    """Create mutation tasks with dependency ordering from a call graph."""
    task_ids = []
    func_to_task: dict[int, int] = {}

    for func in functions:
        addr = resolve_function_address(func)
        name = resolve_function_name(func, addr)
        passes = func.get("passes", [])
        deps = infer_task_dependencies(addr, call_graph, func_to_task)

        task_id = work_queue.add_task(
            function_address=addr,
            function_name=name,
            passes=passes,
            dependencies=deps,
            priority=build_task_priority(deps),
        )

        task_ids.append(task_id)
        func_to_task[addr] = task_id

    return task_ids


def build_mutation_result(
    task_id: int,
    task: MutationTask,
    result_data: dict[str, Any] | None = None,
) -> MutationResult:
    """Build a successful mutation result from worker output."""
    result_data = result_data or {}
    return MutationResult(
        task_id=task_id,
        function_address=task.function_address,
        function_name=task.function_name,
        success=result_data.get("success", True),
        mutations_applied=result_data.get("mutations", []),
        bytes_modified=result_data.get("bytes_modified", 0),
        execution_time=result_data.get("execution_time", 0.0),
    )


def build_failed_mutation_result(
    task_id: int,
    task: MutationTask,
    error: Exception | str,
) -> MutationResult:
    """Build a failed mutation result from an exception."""
    return MutationResult(
        task_id=task_id,
        function_address=task.function_address,
        function_name=task.function_name,
        success=False,
        error=str(error),
    )
