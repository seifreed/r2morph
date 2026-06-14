from r2morph.core.parallel_executor_models import MutationResult, ResolutionStrategy
from r2morph.core.parallel_result_merger_helpers import (
    build_conflict_resolutions,
    collect_conflict_regions,
    detect_conflicts_from_regions,
    summarize_results,
)


def test_summarize_results_uses_conflicts_and_totals() -> None:
    results = [
        MutationResult(
            task_id=1,
            function_address=0x1000,
            function_name="f1",
            success=True,
            mutations_applied=[{"address": 0x10, "size": 4}],
            bytes_modified=4,
            execution_time=1.5,
        )
    ]
    conflicts = [{"function": "0x1000"}]

    merged = summarize_results(results, conflicts)

    assert merged["total_functions"] == 1
    assert merged["successful"] == 1
    assert merged["failed"] == 0
    assert merged["total_mutations"] == 1
    assert merged["total_bytes_modified"] == 4
    assert merged["total_time"] == 1.5
    assert merged["conflicts"] == conflicts


def test_conflict_detection_and_resolution_helpers() -> None:
    results = [
        MutationResult(
            task_id=1,
            function_address=0x1000,
            function_name="f1",
            success=True,
            mutations_applied=[{"address": 0x10, "size": 8}, {"address": 0x14, "size": 8}],
        )
    ]

    regions = collect_conflict_regions(results)
    conflicts = detect_conflicts_from_regions(regions)

    assert conflicts == [
        {
            "function": "0x1000",
            "region1": (0x10, 0x18),
            "region2": (0x14, 0x1C),
            "task_ids": [1, 1],
        }
    ]

    resolutions = build_conflict_resolutions(conflicts, ResolutionStrategy.SKIP)
    assert resolutions[0]["action"] == "skip_second"
    assert resolutions[0]["strategy"] == "skip"
