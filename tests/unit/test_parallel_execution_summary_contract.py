"""Contract tests for parallel execution summary helpers."""

from __future__ import annotations

from r2morph.core.parallel_execution_summary import build_parallel_results_summary
from r2morph.core.parallel_planner import PassResult, PassStatus
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY

_EXPECTED_SUMMARY_TOTAL_DURATION_SECONDS_2_25 = 2.25
_EXPECTED_SUMMARY_TOTAL_MUTATIONS_3 = 3
_EXPECTED_SUMMARY_TOTAL_PASSES_3 = 3


def test_build_parallel_results_summary_counts_outcomes() -> None:
    results = {
        "alpha": PassResult(
            **{MUTATION_NAME_KEY: "alpha"},
            status=PassStatus.COMPLETED,
            mutations_applied=2,
            duration_seconds=1.5,
        ),
        "beta": PassResult(
            **{MUTATION_NAME_KEY: "beta"},
            status=PassStatus.FAILED,
            mutations_applied=0,
            duration_seconds=0.25,
        ),
        "gamma": PassResult(
            **{MUTATION_NAME_KEY: "gamma"},
            status=PassStatus.SKIPPED,
            mutations_applied=1,
            duration_seconds=0.5,
        ),
    }

    summary = build_parallel_results_summary(results)

    expect(summary["total_passes"] == _EXPECTED_SUMMARY_TOTAL_PASSES_3)
    expect(summary["completed"] == 1)
    expect(summary["failed"] == 1)
    expect(summary["skipped"] == 1)
    expect(summary["rolled_back"] == 0)
    expect(summary["total_mutations"] == _EXPECTED_SUMMARY_TOTAL_MUTATIONS_3)
    expect(summary["total_duration_seconds"] == _EXPECTED_SUMMARY_TOTAL_DURATION_SECONDS_2_25)
    expect(summary["passes"]["alpha"]["status"] == "completed")
