from __future__ import annotations

from r2morph.validation import performance_regression_measurement
from r2morph.validation.performance_regression import PerformanceBenchmark


def test_measurement_helpers_delegate_from_benchmark(monkeypatch) -> None:
    benchmark = PerformanceBenchmark()

    monkeypatch.setattr(
        performance_regression_measurement,
        "measure_execution_time",
        lambda config, func, *args, **kwargs: [1.0, 2.0],
    )
    monkeypatch.setattr(
        performance_regression_measurement,
        "measure_memory_usage",
        lambda func, *args, **kwargs: {"current_memory_mb": 1.0, "peak_memory_mb": 2.0},
    )

    assert benchmark.measure_execution_time(lambda: None) == [1.0, 2.0]
    assert benchmark.measure_memory_usage(lambda: None) == {
        "current_memory_mb": 1.0,
        "peak_memory_mb": 2.0,
    }
