"""File export helpers for benchmark results."""

from __future__ import annotations

from r2morph.validation.benchmark_reporting_io import write_csv_export, write_json_export
from r2morph.validation.benchmark_types import BenchmarkResult


def export_results(results: list[BenchmarkResult], output_path: str, format: str = "json") -> None:
    if format.lower() == "json":
        write_json_export(results, output_path)
        return

    if format.lower() == "csv":
        write_csv_export(results, output_path)
        return

    raise ValueError(f"Unsupported export format: {format}")


__all__ = ["export_results", "write_csv_export", "write_json_export"]
