"""Summary math for benchmark reporting."""

from __future__ import annotations

import statistics
from typing import Any

from r2morph.validation.benchmark_types import BenchmarkCategory, BenchmarkResult, TestSeverity


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

    categories: dict[str, Any] = {}
    for category in BenchmarkCategory:
        cat_results = [r for r in results if r.category == category]
        if cat_results:
            cat_success = sum(1 for r in cat_results if r.performance.success)
            cat_times = [r.performance.execution_time for r in cat_results if r.performance.success]
            categories[category.value] = {
                "total": len(cat_results),
                "successful": cat_success,
                "success_rate": cat_success / len(cat_results),
                "avg_time": statistics.mean(cat_times) if cat_times else 0.0,
            }

    severity_breakdown: dict[str, Any] = {}
    for severity in TestSeverity:
        sev_results = [r for r in results if r.sample.severity == severity]
        if sev_results:
            sev_success = sum(1 for r in sev_results if r.performance.success)
            severity_breakdown[severity.value] = {
                "total": len(sev_results),
                "successful": sev_success,
                "success_rate": sev_success / len(sev_results),
            }

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
