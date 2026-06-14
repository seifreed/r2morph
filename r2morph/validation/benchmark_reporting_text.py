"""Human-readable benchmark report formatting."""

from __future__ import annotations

from r2morph.validation.benchmark_reporting_sections import build_benchmark_report_lines
from r2morph.validation.benchmark_reporting_summary import generate_validation_summary
from r2morph.validation.benchmark_types import BenchmarkResult


def generate_report(results: list[BenchmarkResult]) -> str:
    if not results:
        return "No benchmark results available."

    summary = generate_validation_summary(results)
    return "\n".join(build_benchmark_report_lines(summary))


__all__ = ["generate_report"]
