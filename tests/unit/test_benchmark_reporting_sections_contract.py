from r2morph.validation.benchmark_reporting_sections import build_benchmark_report_lines


def test_benchmark_reporting_sections_contract() -> None:
    summary = {
        "total_tests": 2,
        "successful_tests": 1,
        "success_rate": 0.5,
        "avg_execution_time": 31.2,
        "avg_memory_usage": 4.0,
        "avg_accuracy": 0.75,
        "execution_time_percentiles": {"p50": 1.0, "p95": 2.0, "p99": 3.0},
        "categories": {"detection": {"total": 2, "successful": 1, "success_rate": 0.5, "avg_time": 1.2}},
        "severity_breakdown": {"low": {"total": 2, "successful": 1, "success_rate": 0.5}},
    }

    report = build_benchmark_report_lines(summary)

    assert report[0] == "=" * 80
    assert "OVERALL SUMMARY" in report
    assert "P50 (Median):         1.00s" in report
    assert "DETECTION:" in report
    assert "SEVERITY BREAKDOWN" in report
    assert "⚠️  Success rate below 80% - review failed tests" in report
