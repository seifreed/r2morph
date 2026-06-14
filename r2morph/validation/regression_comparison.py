"""Pure comparison helpers for regression validation."""

from __future__ import annotations

from typing import Any


def compare_outputs(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    """Compare expected and actual output dictionaries."""
    issues: list[str] = []

    missing_keys = set(expected.keys()) - set(actual.keys())
    if missing_keys:
        issues.append(f"Missing output keys: {missing_keys}")

    extra_keys = set(actual.keys()) - set(expected.keys())
    if extra_keys:
        issues.append(f"Extra output keys: {extra_keys}")

    for key in expected.keys():
        if key not in actual:
            continue

        if values_differ(expected[key], actual[key], key):
            issues.append(f"Value mismatch for '{key}': expected {expected[key]}, got {actual[key]}")

    return issues


def values_differ(expected: Any, actual: Any, key: str) -> bool:
    """Check whether two regression values differ meaningfully."""
    if isinstance(expected, float) and isinstance(actual, float):
        tolerance = 0.1 if "score" in key else 0.001
        return abs(expected - actual) > tolerance

    if isinstance(expected, list) and isinstance(actual, list):
        if "techniques" in key:
            return set(expected) != set(actual)
        return expected != actual

    return bool(expected != actual)


def compare_performance(baseline: dict[str, float], actual: dict[str, float]) -> list[str]:
    """Compare performance metrics against a baseline."""
    issues: list[str] = []

    for metric, baseline_value in baseline.items():
        if metric.endswith("_max"):
            base_metric = metric[:-4]
            if base_metric in actual and actual[base_metric] > baseline_value:
                issues.append(
                    f"Performance regression: {base_metric} = {actual[base_metric]:.3f}s "
                    f"exceeds maximum {baseline_value:.3f}s"
                )

    return issues
