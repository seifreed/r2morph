from __future__ import annotations

from r2morph.validation.benchmark_metrics_measurement import measure_performance
from tests.utils.assertions import expect

_EXPECTED_RESULT_5 = 5


def test_measure_performance_success_and_failure() -> None:
    metrics, result = measure_performance(lambda x: x + 1, 4)

    expect(result == _EXPECTED_RESULT_5)
    expect(not (metrics.success is not True))
    expect(not (metrics.execution_time < 0))

    failing_metrics, failing_result = measure_performance(lambda: 1 / 0)

    expect(not (failing_result is not None))
    expect(not (failing_metrics.success is not False))
    expect(failing_metrics.error_message is not None)
