"""Overview section builders for benchmark report text output."""

from __future__ import annotations

from typing import Any


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


__all__ = ["build_overall_summary_lines", "build_percentile_lines"]
