from __future__ import annotations

from r2morph.validation.benchmark_metrics_measurement import measure_performance


def test_measure_performance_success_and_failure() -> None:
    metrics, result = measure_performance(lambda x: x + 1, 4)

    assert result == 5
    assert metrics.success is True
    assert metrics.execution_time >= 0

    failing_metrics, failing_result = measure_performance(lambda: 1 / 0)

    assert failing_result is None
    assert failing_metrics.success is False
    assert failing_metrics.error_message is not None
