from __future__ import annotations

from r2morph.validation import performance_regression_comparison
from r2morph.validation.performance_regression_models import PerformanceSnapshot


def test_performance_regression_comparison_detects_regression() -> None:
    current = PerformanceSnapshot(
        commit_hash="cur",
        timestamp="now",
        metrics={"execution_time_ms_mean": 120.0},
        environment={},
        metadata={},
    )
    baseline = PerformanceSnapshot(
        commit_hash="base",
        timestamp="now",
        metrics={"execution_time_ms_mean": 100.0},
        environment={},
        metadata={},
    )

    regressions = performance_regression_comparison.compare_against_baseline(
        current,
        baseline,
        regression_threshold_percent=10.0,
        critical_threshold_percent=25.0,
    )

    assert len(regressions) == 1
    assert regressions[0].metric_name == "execution_time_ms_mean"
    assert regressions[0].severity == "minor"
