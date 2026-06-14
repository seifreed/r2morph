"""Contract tests for benchmark category runner helpers."""

from __future__ import annotations

from types import SimpleNamespace

from r2morph.validation.benchmark_runners import (
    benchmark_detection,
    benchmark_devirtualization,
    benchmark_full_pipeline,
)
from r2morph.validation.benchmark_types import BenchmarkCategory, PerformanceMetrics, TestSample, TestSeverity


def _performance() -> PerformanceMetrics:
    return PerformanceMetrics(
        execution_time=1.0,
        memory_usage_mb=2.0,
        cpu_usage_percent=3.0,
        peak_memory_mb=4.0,
        success=True,
    )


def test_detection_runner_builds_result(tmp_path) -> None:
    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"abc")
    sample = TestSample(
        file_path=str(sample_file),
        sample_hash="hash",
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=TestSeverity.LOW,
        description="sample",
        source="unit",
    )

    def measure_performance(func):
        return _performance(), func()

    result = benchmark_detection(
        sample,
        measure_performance=measure_performance,
        calculate_accuracy_metrics=lambda expected, actual: SimpleNamespace(accuracy=1.0),
    )

    assert result.category == BenchmarkCategory.DETECTION
    assert result.performance.success is True


def test_full_pipeline_runner_builds_result(tmp_path) -> None:
    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"abc")
    sample = TestSample(
        file_path=str(sample_file),
        sample_hash="hash",
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=TestSeverity.LOW,
        description="sample",
        source="unit",
    )

    def measure_performance(func):
        return _performance(), func()

    result = benchmark_full_pipeline(
        sample,
        measure_performance=measure_performance,
        calculate_accuracy_metrics=lambda expected, actual: SimpleNamespace(accuracy=1.0),
    )

    assert result.category == BenchmarkCategory.FULL_PIPELINE
    assert result.performance.success is True


def test_devirtualization_runner_builds_result(tmp_path) -> None:
    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"abc")
    sample = TestSample(
        file_path=str(sample_file),
        sample_hash="hash",
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=TestSeverity.LOW,
        description="sample",
        source="unit",
    )

    def measure_performance(func):
        return _performance(), {}

    result = benchmark_devirtualization(sample, measure_performance=measure_performance)

    assert result.category == BenchmarkCategory.DEVIRTUALIZATION
    assert result.performance.success is True
