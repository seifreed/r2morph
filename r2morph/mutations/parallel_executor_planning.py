"""Pure task-planning helpers for the parallel mutation executor."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from r2morph.mutations.base import MutationPass


@dataclass(frozen=True)
class MutationTaskPlan:
    """Immutable description of a parallel mutation task."""

    pass_instance: MutationPass
    pass_name: str
    function_addresses: list[int]
    config: dict[str, Any]


def chunk_functions(functions: list[dict[str, Any]], chunk_size: int) -> list[list[dict[str, Any]]]:
    """Split functions into fixed-size chunks."""

    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    return [functions[index : index + chunk_size] for index in range(0, len(functions), chunk_size)]


def build_task_plans(
    passes: list[MutationPass],
    functions: list[dict[str, Any]],
    chunk_size: int,
) -> list[MutationTaskPlan]:
    """Build task plans for enabled mutation passes."""

    plans: list[MutationTaskPlan] = []
    for pass_instance in passes:
        if not pass_instance.enabled:
            continue

        for func_chunk in chunk_functions(functions, chunk_size):
            plans.append(
                MutationTaskPlan(
                    pass_instance=pass_instance,
                    pass_name=pass_instance.name,
                    function_addresses=[function.get("addr", 0) for function in func_chunk],
                    config=pass_instance.config.copy(),
                )
            )

    return plans
