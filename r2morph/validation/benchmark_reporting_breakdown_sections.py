"""Breakdown section builders for benchmark report text output."""

from __future__ import annotations

from typing import Any


def build_category_breakdown_lines(summary: dict[str, Any]) -> list[str]:
    if not summary["categories"]:
        return []

    lines = ["CATEGORY BREAKDOWN", "-" * 40]
    for category, stats in summary["categories"].items():
        lines.append(f"{category.upper()}:")
        lines.append(f"  Tests:       {stats['total']}")
        lines.append(f"  Success:     {stats['successful']} ({stats['success_rate']:.1%})")
        lines.append(f"  Avg Time:    {stats['avg_time']:.2f}s")
        lines.append("")
    return lines


def build_severity_breakdown_lines(summary: dict[str, Any]) -> list[str]:
    if not summary["severity_breakdown"]:
        return []

    lines = ["SEVERITY BREAKDOWN", "-" * 40]
    for severity, stats in summary["severity_breakdown"].items():
        lines.append(f"{severity.upper()}:")
        lines.append(f"  Tests:       {stats['total']}")
        lines.append(f"  Success:     {stats['successful']} ({stats['success_rate']:.1%})")
        lines.append("")
    return lines


__all__ = ["build_category_breakdown_lines", "build_severity_breakdown_lines"]
