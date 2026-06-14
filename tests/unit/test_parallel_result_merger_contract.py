"""Contract tests for parallel result merger helpers."""

from __future__ import annotations

from r2morph.core.parallel_executor_models import MutationResult, ResolutionStrategy
from r2morph.core.parallel_result_merger import ResultMerger


def test_result_merger_aggregates_and_detects_conflicts() -> None:
    merger = ResultMerger()

    left = MutationResult(
        task_id=1,
        function_address=0x1000,
        function_name="left",
        success=True,
        mutations_applied=[{"address": 0x10, "size": 4}],
        bytes_modified=4,
        execution_time=0.5,
    )
    right = MutationResult(
        task_id=2,
        function_address=0x1000,
        function_name="right",
        success=True,
        mutations_applied=[{"address": 0x12, "size": 4}],
        bytes_modified=4,
        execution_time=0.25,
    )

    merger.add_result(left)
    merger.add_result(right)

    conflicts = merger.detect_conflicts([left, right])
    assert conflicts

    merged = merger.merge(None)
    assert merged["total_functions"] == 2
    assert merged["successful"] == 2
    assert merged["total_bytes_modified"] == 8

    resolutions = merger.resolve_conflicts(conflicts, ResolutionStrategy.SKIP)
    assert resolutions[0]["action"] == "skip_second"
