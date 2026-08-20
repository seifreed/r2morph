from r2morph.validation.benchmark_reporting_sections import build_benchmark_report_lines
from tests.utils.assertions import expect


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

    expect(report[0] == "=" * 80)
    expect(not ("OVERALL SUMMARY" not in report))
    expect(not ("P50 (Median):         1.00s" not in report))
    expect(not ("DETECTION:" not in report))
    expect(not ("SEVERITY BREAKDOWN" not in report))
    expect(not ("⚠️  Success rate below 80% - review failed tests" not in report))
