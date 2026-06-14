"""Pure policy helpers for parallel executor task creation."""

from __future__ import annotations

from typing import Any


def resolve_function_address(func: dict[str, Any]) -> int:
    """Resolve a function address from task input."""
    return func.get("offset", func.get("addr", 0))


def resolve_function_name(func: dict[str, Any], addr: int) -> str:
    """Resolve a function name from task input."""
    return func.get("name", f"func_{addr:x}")


def infer_task_dependencies(
    addr: int,
    call_graph: dict[int, list[int]] | None,
    func_to_task: dict[int, int],
) -> list[int]:
    """Infer queue dependencies for a function address."""
    deps: list[int] = []
    if call_graph and addr in call_graph:
        for caller in call_graph:
            if addr in call_graph[caller] and caller in func_to_task:
                deps.append(func_to_task[caller])
    return deps


def build_task_priority(dependencies: list[int]) -> int:
    """Compute task priority from dependency count."""
    return len(dependencies)
