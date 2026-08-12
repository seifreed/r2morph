"""Recommendation helpers for benchmark report text output."""

from __future__ import annotations

from typing import Any

_MIN_ACCEPTABLE_RATE = 0.8
_MAX_AVERAGE_EXECUTION_SECONDS = 30


def build_recommendation_lines(summary: dict[str, Any]) -> list[str]:
    lines = ["RECOMMENDATIONS", "-" * 40]

    if summary["success_rate"] < _MIN_ACCEPTABLE_RATE:
        lines.append("⚠️  Success rate below 80% - review failed tests")
    else:
        lines.append("✅ Good success rate")

    if summary["avg_execution_time"] > _MAX_AVERAGE_EXECUTION_SECONDS:
        lines.append("⚠️  Average execution time > 30s - consider optimization")
    else:
        lines.append("✅ Good performance")

    if summary["avg_accuracy"] < _MIN_ACCEPTABLE_RATE:
        lines.append("⚠️  Average accuracy below 80% - review detection algorithms")
    else:
        lines.append("✅ Good accuracy")

    lines.append("")
    return lines
