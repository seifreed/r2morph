"""Recommendation helpers for benchmark report text output."""

from __future__ import annotations

from typing import Any


def build_recommendation_lines(summary: dict[str, Any]) -> list[str]:
    lines = ["RECOMMENDATIONS", "-" * 40]

    if summary["success_rate"] < 0.8:
        lines.append("⚠️  Success rate below 80% - review failed tests")
    else:
        lines.append("✅ Good success rate")

    if summary["avg_execution_time"] > 30:
        lines.append("⚠️  Average execution time > 30s - consider optimization")
    else:
        lines.append("✅ Good performance")

    if summary["avg_accuracy"] < 0.8:
        lines.append("⚠️  Average accuracy below 80% - review detection algorithms")
    else:
        lines.append("✅ Good accuracy")

    lines.append("")
    return lines
