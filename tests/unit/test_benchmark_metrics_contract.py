"""Contract tests for benchmark metric helpers."""

from __future__ import annotations

from r2morph.validation.benchmark_metrics import (
    calculate_accuracy_metrics,
    measure_performance,
)


def test_measure_performance_success_and_failure() -> None:
    metrics, result = measure_performance(lambda x: x + 1, 4)

    assert result == 5
    assert metrics.success is True
    assert metrics.execution_time >= 0

    failing_metrics, failing_result = measure_performance(lambda: 1 / 0)

    assert failing_result is None
    assert failing_metrics.success is False
    assert failing_metrics.error_message is not None


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

    assert metrics.true_positives == 1
    assert metrics.false_positives == 1
    assert metrics.true_negatives == 3
    assert metrics.false_negatives == 0
    assert metrics.accuracy == 0.8
