from __future__ import annotations

import hashlib

from r2morph.validation.benchmark_reporting_breakdown import build_category_breakdown, build_severity_breakdown
from r2morph.validation.benchmark_types import (
    AccuracyMetrics,
    BenchmarkCategory,
    BenchmarkResult,
    PerformanceMetrics,
    TestSample,
    TestSeverity,
)


def _make_result(category: BenchmarkCategory, severity: TestSeverity) -> BenchmarkResult:
    sample = TestSample(
        file_path="sample.bin",
        sample_hash=hashlib.sha256(b"abc").hexdigest(),
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=severity,
        description="benchmark",
        source="unit_test",
    )
    performance = PerformanceMetrics(1.5, 2.0, 3.0, 4.0, True, None)
    accuracy = AccuracyMetrics(1, 0, 4, 0, 1.0, 1.0, 1.0, 1.0)
    return BenchmarkResult(sample, category, performance, accuracy, {"ok": True}, "now", "dev")


def test_breakdown_helpers_group_results() -> None:
    results = [
        _make_result(BenchmarkCategory.DETECTION, TestSeverity.LOW),
        _make_result(BenchmarkCategory.DETECTION, TestSeverity.LOW),
        _make_result(BenchmarkCategory.FULL_PIPELINE, TestSeverity.HIGH),
    ]

    categories = build_category_breakdown(results)
    severities = build_severity_breakdown(results)

    assert categories["detection"]["total"] == 2
    assert severities["low"]["total"] == 2
    assert severities["high"]["total"] == 1
