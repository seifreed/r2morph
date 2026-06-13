"""Reporting helpers for benchmark results."""

from __future__ import annotations

import csv
import json
import statistics
import time
from dataclasses import asdict
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


def export_results(results: list[BenchmarkResult], output_path: str, format: str = "json") -> None:
    if format.lower() == "json":
        export_data = {
            "metadata": {
                "export_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "r2morph_version": "2.0.0-phase2",
                "total_results": len(results),
            },
            "summary": generate_validation_summary(results),
            "results": [asdict(result) for result in results],
        }

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2, default=str)
        return

    if format.lower() == "csv":
        try:
            with open(output_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "sample_path",
                        "sample_hash",
                        "category",
                        "success",
                        "execution_time",
                        "memory_usage_mb",
                        "accuracy",
                        "precision",
                        "recall",
                        "f1_score",
                        "timestamp",
                    ]
                )
                for result in results:
                    writer.writerow(
                        [
                            result.sample.file_path,
                            result.sample.sample_hash,
                            result.category.value,
                            result.performance.success,
                            result.performance.execution_time,
                            result.performance.memory_usage_mb,
                            result.accuracy.accuracy if result.accuracy else "",
                            result.accuracy.precision if result.accuracy else "",
                            result.accuracy.recall if result.accuracy else "",
                            result.accuracy.f1_score if result.accuracy else "",
                            result.timestamp,
                        ]
                    )
        except ImportError:
            with open(output_path, "w") as f:
                f.write("sample_path,category,success,execution_time,memory_usage_mb,timestamp\n")
                for result in results:
                    f.write(
                        f"{result.sample.file_path},{result.category.value},"
                        f"{result.performance.success},{result.performance.execution_time},"
                        f"{result.performance.memory_usage_mb},{result.timestamp}\n"
                    )
        return

    raise ValueError(f"Unsupported export format: {format}")


def generate_report(results: list[BenchmarkResult]) -> str:
    if not results:
        return "No benchmark results available."

    summary = generate_validation_summary(results)
    report = []
    report.append("=" * 80)
    report.append("R2MORPH VALIDATION REPORT")
    report.append("=" * 80)
    report.append("")

    report.append("OVERALL SUMMARY")
    report.append("-" * 40)
    report.append(f"Total Tests:          {summary['total_tests']}")
    report.append(f"Successful Tests:     {summary['successful_tests']}")
    report.append(f"Success Rate:         {summary['success_rate']:.1%}")
    report.append(f"Average Execution:    {summary['avg_execution_time']:.2f}s")
    report.append(f"Average Memory:       {summary['avg_memory_usage']:.1f}MB")
    report.append(f"Average Accuracy:     {summary['avg_accuracy']:.1%}")
    report.append("")

    report.append("PERFORMANCE PERCENTILES")
    report.append("-" * 40)
    percentiles = summary["execution_time_percentiles"]
    report.append(f"P50 (Median):         {percentiles['p50']:.2f}s")
    report.append(f"P95:                  {percentiles['p95']:.2f}s")
    report.append(f"P99:                  {percentiles['p99']:.2f}s")
    report.append("")

    if summary["categories"]:
        report.append("CATEGORY BREAKDOWN")
        report.append("-" * 40)
        for category, stats in summary["categories"].items():
            report.append(f"{category.upper()}:")
            report.append(f"  Tests:       {stats['total']}")
            report.append(f"  Success:     {stats['successful']} ({stats['success_rate']:.1%})")
            report.append(f"  Avg Time:    {stats['avg_time']:.2f}s")
            report.append("")

    if summary["severity_breakdown"]:
        report.append("SEVERITY BREAKDOWN")
        report.append("-" * 40)
        for severity, stats in summary["severity_breakdown"].items():
            report.append(f"{severity.upper()}:")
            report.append(f"  Tests:       {stats['total']}")
            report.append(f"  Success:     {stats['successful']} ({stats['success_rate']:.1%})")
            report.append("")

    report.append("RECOMMENDATIONS")
    report.append("-" * 40)

    if summary["success_rate"] < 0.8:
        report.append("⚠️  Success rate below 80% - review failed tests")
    else:
        report.append("✅ Good success rate")

    if summary["avg_execution_time"] > 30:
        report.append("⚠️  Average execution time > 30s - consider optimization")
    else:
        report.append("✅ Good performance")

    if summary["avg_accuracy"] < 0.8:
        report.append("⚠️  Average accuracy below 80% - review detection algorithms")
    else:
        report.append("✅ Good accuracy")

    report.append("")
    report.append("=" * 80)
    return "\n".join(report)
