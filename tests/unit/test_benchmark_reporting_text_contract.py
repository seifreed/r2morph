"""Contract tests for benchmark report text helpers."""

from __future__ import annotations

import hashlib

from r2morph.validation.benchmark_reporting_text import generate_report
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


def test_generate_report_renders_summary_sections(tmp_path) -> None:
    result = _make_result(tmp_path)
    report = generate_report([result])

    assert "R2MORPH VALIDATION REPORT" in report
    assert "OVERALL SUMMARY" in report
    assert "CATEGORY BREAKDOWN" in report
    assert "RECOMMENDATIONS" in report
