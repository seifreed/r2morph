"""Section builders for benchmark report text output."""

from __future__ import annotations

from typing import Any

from r2morph.validation.benchmark_reporting_breakdown_sections import (
    build_category_breakdown_lines,
    build_severity_breakdown_lines,
)
from r2morph.validation.benchmark_reporting_overview import build_overall_summary_lines, build_percentile_lines
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


__all__ = [
    "build_benchmark_report_lines",
    "build_category_breakdown_lines",
    "build_overall_summary_lines",
    "build_percentile_lines",
    "build_recommendation_lines",
    "build_severity_breakdown_lines",
]
