from r2morph.core.parallel_executor_models import MutationResult, ResolutionStrategy
from r2morph.core.parallel_result_merger_helpers import (
    build_conflict_resolutions,
    collect_conflict_regions,
    detect_conflicts_from_regions,
    summarize_results,
)
from tests.utils.assertions import expect

_EXPECTED_MERGED_TOTAL_BYTES_MODIFIED_4 = 4
_EXPECTED_MERGED_TOTAL_TIME_1_5 = 1.5


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

    expect(merged["total_functions"] == 1)
    expect(merged["successful"] == 1)
    expect(merged["failed"] == 0)
    expect(merged["total_mutations"] == 1)
    expect(merged["total_bytes_modified"] == _EXPECTED_MERGED_TOTAL_BYTES_MODIFIED_4)
    expect(merged["total_time"] == _EXPECTED_MERGED_TOTAL_TIME_1_5)
    expect(merged["conflicts"] == conflicts)


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

    expect(conflicts == [{"function": "0x1000", "region1": (16, 24), "region2": (20, 28), "task_ids": [1, 1]}])

    resolutions = build_conflict_resolutions(conflicts, ResolutionStrategy.SKIP)
    expect(resolutions[0]["action"] == "skip_second")
    expect(resolutions[0]["strategy"] == "skip")
