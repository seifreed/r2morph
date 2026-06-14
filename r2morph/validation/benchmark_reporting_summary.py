"""Summary math for benchmark reporting."""

from __future__ import annotations

import statistics
from typing import Any

from r2morph.validation.benchmark_reporting_breakdown import build_category_breakdown, build_severity_breakdown
from r2morph.validation.benchmark_types import BenchmarkResult


def calculate_percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    n = 100 if percentile >= 99 else 20
    index = (n * percentile) // 100 - 1
    if len(values) >= n:
        return statistics.quantiles(values, n=n)[index]
    return max(values)


def generate_validation_summary(results: list[BenchmarkResult]) -> dict[str, Any]:
    if not results:
        return {
            "total_tests": 0,
            "successful_tests": 0,
            "success_rate": 0.0,
            "avg_execution_time": 0.0,
            "avg_memory_usage": 0.0,
            "avg_accuracy": 0.0,
            "categories": {},
            "severity_breakdown": {},
            "execution_time_percentiles": {"p50": 0.0, "p95": 0.0, "p99": 0.0},
        }

    total_tests = len(results)
    successful_tests = sum(1 for r in results if r.performance.success)
    success_rate = successful_tests / total_tests

    execution_times = [r.performance.execution_time for r in results if r.performance.success]
    avg_execution_time = statistics.mean(execution_times) if execution_times else 0.0

    memory_usages = [r.performance.memory_usage_mb for r in results if r.performance.success]
    avg_memory_usage = statistics.mean(memory_usages) if memory_usages else 0.0

    accuracy_scores = [r.accuracy.accuracy for r in results if r.accuracy is not None]
    avg_accuracy = statistics.mean(accuracy_scores) if accuracy_scores else 0.0

    categories = build_category_breakdown(results)
    severity_breakdown = build_severity_breakdown(results)

    return {
        "total_tests": total_tests,
        "successful_tests": successful_tests,
        "success_rate": success_rate,
        "avg_execution_time": avg_execution_time,
        "avg_memory_usage": avg_memory_usage,
        "avg_accuracy": avg_accuracy,
        "categories": categories,
        "severity_breakdown": severity_breakdown,
        "execution_time_percentiles": {
            "p50": statistics.median(execution_times) if execution_times else 0.0,
            "p95": calculate_percentile(execution_times, 95),
            "p99": calculate_percentile(execution_times, 99),
        },
    }


__all__ = ["calculate_percentile", "generate_validation_summary"]
