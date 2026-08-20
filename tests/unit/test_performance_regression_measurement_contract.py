from __future__ import annotations

from r2morph.validation.performance_regression import PerformanceBenchmark
from r2morph.validation.performance_regression_models import BenchmarkConfig
from tests.utils.assertions import expect

_EXPECTED_LEN_CALLS_3 = 3
_EXPECTED_LEN_TIMINGS_2 = 2


def test_measurement_helpers_execute_real_callable() -> None:
    benchmark = PerformanceBenchmark(BenchmarkConfig(warmup_runs=0, measured_runs=2))
    calls: list[None] = []

    def record_call() -> None:
        calls.append(None)

    timings = benchmark.measure_execution_time(record_call)
    memory = benchmark.measure_memory_usage(record_call)

    expect(
        len(timings) == _EXPECTED_LEN_TIMINGS_2
        and len(calls) == _EXPECTED_LEN_CALLS_3
        and set(memory) == {"current_memory_mb", "peak_memory_mb"}
    )
