"""Contract tests for parallel execution summary helpers."""

from __future__ import annotations

from r2morph.core.parallel_execution_summary import build_parallel_results_summary
from r2morph.core.parallel_planner import PassResult, PassStatus


def test_build_parallel_results_summary_counts_outcomes() -> None:
    results = {
        "alpha": PassResult(
            pass_name="alpha",
            status=PassStatus.COMPLETED,
            mutations_applied=2,
            duration_seconds=1.5,
        ),
        "beta": PassResult(
            pass_name="beta",
            status=PassStatus.FAILED,
            mutations_applied=0,
            duration_seconds=0.25,
        ),
        "gamma": PassResult(
            pass_name="gamma",
            status=PassStatus.SKIPPED,
            mutations_applied=1,
            duration_seconds=0.5,
        ),
    }

    summary = build_parallel_results_summary(results)

    assert summary["total_passes"] == 3
    assert summary["completed"] == 1
    assert summary["failed"] == 1
    assert summary["skipped"] == 1
    assert summary["rolled_back"] == 0
    assert summary["total_mutations"] == 3
    assert summary["total_duration_seconds"] == 2.25
    assert summary["passes"]["alpha"]["status"] == "completed"
