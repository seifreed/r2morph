from r2morph.validation.benchmark_reporting_overview import (
    build_overall_summary_lines,
    build_percentile_lines,
)


def test_benchmark_reporting_overview_contract() -> None:
    summary = {
        "total_tests": 2,
        "successful_tests": 1,
        "success_rate": 0.5,
        "avg_execution_time": 31.2,
        "avg_memory_usage": 4.0,
        "avg_accuracy": 0.75,
        "execution_time_percentiles": {"p50": 1.0, "p95": 2.0, "p99": 3.0},
    }

    overview = build_overall_summary_lines(summary)
    percentiles = build_percentile_lines(summary)

    assert overview[0] == "OVERALL SUMMARY"
    assert "Average Memory:       4.0MB" in overview
    assert percentiles[0] == "PERFORMANCE PERCENTILES"
    assert "P99:                  3.00s" in percentiles
