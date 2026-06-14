"""File export helpers for benchmark results."""

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


__all__ = ["export_results"]
