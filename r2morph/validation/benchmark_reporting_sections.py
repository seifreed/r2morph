"""Section builders for benchmark report text output."""

from __future__ import annotations

from typing import Any

from r2morph.validation.benchmark_reporting_recommendations import build_recommendation_lines


def build_benchmark_report_lines(summary: dict[str, Any]) -> list[str]:
    """Render a benchmark summary dict into report lines."""
    report = [
        "=" * 80,
        "R2MORPH VALIDATION REPORT",
        "=" * 80,
        "",
    ]
    report.extend(build_overall_summary_lines(summary))
    report.extend(build_percentile_lines(summary))
    report.extend(build_category_breakdown_lines(summary))
    report.extend(build_severity_breakdown_lines(summary))
    report.extend(build_recommendation_lines(summary))
    report.append("=" * 80)
    return report


def build_overall_summary_lines(summary: dict[str, Any]) -> list[str]:
    return [
        "OVERALL SUMMARY",
        "-" * 40,
        f"Total Tests:          {summary['total_tests']}",
        f"Successful Tests:     {summary['successful_tests']}",
        f"Success Rate:         {summary['success_rate']:.1%}",
        f"Average Execution:    {summary['avg_execution_time']:.2f}s",
        f"Average Memory:       {summary['avg_memory_usage']:.1f}MB",
        f"Average Accuracy:     {summary['avg_accuracy']:.1%}",
        "",
    ]


def build_percentile_lines(summary: dict[str, Any]) -> list[str]:
    percentiles = summary["execution_time_percentiles"]
    return [
        "PERFORMANCE PERCENTILES",
        "-" * 40,
        f"P50 (Median):         {percentiles['p50']:.2f}s",
        f"P95:                  {percentiles['p95']:.2f}s",
        f"P99:                  {percentiles['p99']:.2f}s",
        "",
    ]


def build_category_breakdown_lines(summary: dict[str, Any]) -> list[str]:
    if not summary["categories"]:
        return []

    lines = ["CATEGORY BREAKDOWN", "-" * 40]
    for category, stats in summary["categories"].items():
        lines.append(f"{category.upper()}:")
        lines.append(f"  Tests:       {stats['total']}")
        lines.append(f"  Success:     {stats['successful']} ({stats['success_rate']:.1%})")
        lines.append(f"  Avg Time:    {stats['avg_time']:.2f}s")
        lines.append("")
    return lines


def build_severity_breakdown_lines(summary: dict[str, Any]) -> list[str]:
    if not summary["severity_breakdown"]:
        return []

    lines = ["SEVERITY BREAKDOWN", "-" * 40]
    for severity, stats in summary["severity_breakdown"].items():
        lines.append(f"{severity.upper()}:")
        lines.append(f"  Tests:       {stats['total']}")
        lines.append(f"  Success:     {stats['successful']} ({stats['success_rate']:.1%})")
        lines.append("")
    return lines


__all__ = [
    "build_benchmark_report_lines",
    "build_category_breakdown_lines",
    "build_overall_summary_lines",
    "build_percentile_lines",
    "build_recommendation_lines",
    "build_severity_breakdown_lines",
]
