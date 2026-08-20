"""Contract tests for benchmark metric helpers."""

from __future__ import annotations

from r2morph.validation.benchmark_metrics import (
    calculate_accuracy_metrics,
    measure_performance,
)
from tests.utils.assertions import expect

_EXPECTED_METRICS_ACCURACY_0_8 = 0.8
_EXPECTED_METRICS_TRUE_NEGATIVES_3 = 3
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


def test_calculate_accuracy_metrics_counts_expected_fields() -> None:
    metrics = calculate_accuracy_metrics(
        {
            "packer_detected": True,
            "vm_protection": False,
            "anti_analysis": False,
            "cfo_detected": False,
            "mba_detected": False,
        },
        {
            "packer_detected": True,
            "vm_protection": True,
            "anti_analysis": False,
            "cfo_detected": False,
            "mba_detected": False,
        },
    )

    expect(metrics.true_positives == 1)
    expect(metrics.false_positives == 1)
    expect(metrics.true_negatives == _EXPECTED_METRICS_TRUE_NEGATIVES_3)
    expect(metrics.false_negatives == 0)
    expect(metrics.accuracy == _EXPECTED_METRICS_ACCURACY_0_8)
