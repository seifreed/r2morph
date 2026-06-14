"""Contract tests for benchmark reporting summary helpers."""

from __future__ import annotations

import hashlib

from r2morph.validation.benchmark_reporting_summary import (
    calculate_percentile,
    generate_validation_summary,
)
from r2morph.validation.benchmark_types import (
    AccuracyMetrics,
    BenchmarkCategory,
    BenchmarkResult,
    PerformanceMetrics,
    TestSample,
    TestSeverity,
)


def _make_result(tmp_path):
    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"abc")
    sample_hash = hashlib.sha256(sample_file.read_bytes()).hexdigest()
    sample = TestSample(
        file_path=str(sample_file),
        sample_hash=sample_hash,
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=TestSeverity.LOW,
        description="benchmark",
        source="unit_test",
    )
    performance = PerformanceMetrics(
        execution_time=1.5,
        memory_usage_mb=2.0,
        cpu_usage_percent=3.0,
        peak_memory_mb=4.0,
        success=True,
        error_message=None,
    )
    accuracy = AccuracyMetrics(1, 0, 4, 0, 1.0, 1.0, 1.0, 1.0)
    return BenchmarkResult(sample, BenchmarkCategory.DETECTION, performance, accuracy, {"ok": True}, "now", "dev")


def test_percentile_helper_handles_empty_and_populated_inputs() -> None:
    assert calculate_percentile([], 95) == 0.0
    assert calculate_percentile([1.0, 2.0, 3.0], 95) == 3.0


def test_generate_validation_summary_shapes_results(tmp_path) -> None:
    result = _make_result(tmp_path)
    summary = generate_validation_summary([result])

    assert summary["total_tests"] == 1
    assert summary["categories"]["detection"]["total"] == 1
    assert summary["severity_breakdown"]["low"]["total"] == 1
