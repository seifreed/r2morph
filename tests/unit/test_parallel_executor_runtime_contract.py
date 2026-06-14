from __future__ import annotations

import logging
from dataclasses import dataclass, field

from r2morph.mutations.parallel_executor import ParallelStats
from r2morph.mutations.parallel_executor_runtime import execute_parallel_runs


@dataclass
class _Task:
    pass_name: str


@dataclass
class _Result:
    success: bool = True
    mutations_applied: int = 0
    records: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class _Binary:
    def __init__(self) -> None:
        self.path = "/tmp/binary"

    def get_functions(self) -> list[dict[str, int]]:
        return [{"addr": 1}]


def test_parallel_executor_runtime_collects_success_and_failure() -> None:
    def create_tasks(passes, functions):
        return [_Task("ok"), _Task("bad")]

    def execute_task(task, binary_path):
        if task.pass_name == "ok":
            return _Result(success=True, mutations_applied=2, records=["r1", "r2"])
        return _Result(success=False, errors=["boom"])

    records, stats = execute_parallel_runs(
        passes=[object()],
        binary=_Binary(),
        max_workers=2,
        timeout=5.0,
        create_tasks=create_tasks,
        execute_task=execute_task,
        stats_factory=ParallelStats,
        logger=logging.getLogger(__name__),
    )

    assert records == ["r1", "r2"]
    assert stats.tasks_completed == 1
    assert stats.tasks_failed == 1
    assert stats.total_mutations == 2
