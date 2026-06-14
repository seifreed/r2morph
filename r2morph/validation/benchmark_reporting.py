"""Reporting helpers for benchmark results."""

from __future__ import annotations

import csv
import json
import time
from dataclasses import asdict

from r2morph.validation.benchmark_reporting_summary import generate_validation_summary
from r2morph.validation.benchmark_types import BenchmarkResult


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
