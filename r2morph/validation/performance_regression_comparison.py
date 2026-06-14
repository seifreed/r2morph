"""Comparison helpers for performance regression validation."""

from __future__ import annotations

from r2morph.validation.performance_regression_models import PerformanceRegression, PerformanceSnapshot


def compare_against_baseline(
    current: PerformanceSnapshot,
    baseline: PerformanceSnapshot,
    regression_threshold_percent: float,
    critical_threshold_percent: float,
) -> list[PerformanceRegression]:
    """Compare current performance against a baseline snapshot."""
    regressions = []

    for metric_name, baseline_value in baseline.metrics.items():
        if metric_name not in current.metrics:
            continue

        current_value = current.metrics[metric_name]

        if baseline_value == 0:
            continue

        percentage_change = ((current_value - baseline_value) / baseline_value) * 100

        if percentage_change > regression_threshold_percent:
            severity = "minor"
            if percentage_change > critical_threshold_percent:
                severity = "critical"
            elif percentage_change > regression_threshold_percent * 2:
                severity = "major"

            regressions.append(
                PerformanceRegression(
                    metric_name=metric_name,
                    baseline_value=baseline_value,
                    current_value=current_value,
                    threshold=regression_threshold_percent,
                    percentage_change=percentage_change,
                    severity=severity,
                )
            )

    return regressions
