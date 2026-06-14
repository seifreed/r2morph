"""Benchmark reporting breakdown helpers."""

from __future__ import annotations

import statistics
from typing import Any

from r2morph.validation.benchmark_types import BenchmarkCategory, BenchmarkResult, TestSeverity


def build_category_breakdown(results: list[BenchmarkResult]) -> dict[str, Any]:
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
    return categories


def build_severity_breakdown(results: list[BenchmarkResult]) -> dict[str, Any]:
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
    return severity_breakdown
