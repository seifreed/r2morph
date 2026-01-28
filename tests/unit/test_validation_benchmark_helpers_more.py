from __future__ import annotations

import hashlib
import json
from pathlib import Path

from r2morph.validation.benchmark import (
    AccuracyMetrics,
    BenchmarkCategory,
    BenchmarkResult,
    PerformanceMetrics,
    TestSample,
    TestSeverity,
    ValidationFramework,
)


def _make_sample(tmp_path: Path) -> TestSample:
    sample_path = tmp_path / "sample.bin"
    sample_path.write_bytes(b"r2morph-test")
    sample_hash = hashlib.sha256(sample_path.read_bytes()).hexdigest()
    return TestSample(
        file_path=str(sample_path),
        sample_hash=sample_hash,
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=TestSeverity.LOW,
        description="unit sample",
        source="unit",
    )


def test_test_sample_hash_and_existence(tmp_path: Path) -> None:
    sample = _make_sample(tmp_path)
    assert sample.file_exists is True
    assert sample.verify_hash() is True

    bad_sample = TestSample(
        file_path=sample.file_path,
        sample_hash="00" * 32,
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=TestSeverity.LOW,
        description="bad hash",
        source="unit",
    )
    assert bad_sample.verify_hash() is False


def test_benchmark_accuracy_metrics_calculation() -> None:
    framework = ValidationFramework(test_data_dir="dataset")
    expected = {
        "packer_detected": True,
        "vm_protection": True,
        "anti_analysis": False,
        "cfo_detected": True,
        "mba_detected": False,
    }
    actual = {
        "packer_detected": True,
        "vm_protection": False,
        "anti_analysis": False,
        "cfo_detected": True,
        "mba_detected": True,
    }
    metrics = framework._calculate_accuracy_metrics(expected, actual)
    assert metrics.true_positives == 2
    assert metrics.false_positives == 1
    assert metrics.true_negatives == 1
    assert metrics.false_negatives == 1
    assert 0.0 <= metrics.accuracy <= 1.0


def test_benchmark_percentile_and_summary(tmp_path: Path) -> None:
    framework = ValidationFramework(test_data_dir="dataset")
    assert framework._calculate_percentile([], 95) == 0.0
    assert framework._calculate_percentile([1.0, 2.0, 3.0], 95) == 3.0
    assert framework._calculate_percentile(list(range(1, 101)), 99) >= 1.0

    sample = _make_sample(tmp_path)
    perf_ok = PerformanceMetrics(0.5, 10.0, 0.0, 0.0, True, None)
    perf_fail = PerformanceMetrics(1.0, 5.0, 0.0, 0.0, False, "fail")
    acc = AccuracyMetrics(1, 0, 1, 0, 1.0, 1.0, 1.0, 1.0)
    results = [
        BenchmarkResult(sample, BenchmarkCategory.DETECTION, perf_ok, acc, {}, "now", "dev"),
        BenchmarkResult(sample, BenchmarkCategory.FULL_PIPELINE, perf_fail, None, {}, "now", "dev"),
    ]
    summary = framework._generate_validation_summary(results)
    assert summary["total_tests"] == 2
    assert summary["success_rate"] == 0.5
    assert summary["categories"]


def test_benchmark_export_formats(tmp_path: Path) -> None:
    framework = ValidationFramework(test_data_dir="dataset")
    sample = _make_sample(tmp_path)
    perf_ok = PerformanceMetrics(0.25, 3.0, 0.0, 0.0, True, None)
    acc = AccuracyMetrics(1, 0, 1, 0, 1.0, 1.0, 1.0, 1.0)
    framework.benchmark_results = [
        BenchmarkResult(sample, BenchmarkCategory.DETECTION, perf_ok, acc, {}, "now", "dev")
    ]

    json_path = tmp_path / "bench.json"
    csv_path = tmp_path / "bench.csv"
    framework.export_results(str(json_path), format="json")
    framework.export_results(str(csv_path), format="csv")

    assert json_path.exists()
    assert csv_path.exists()
    data = json.loads(json_path.read_text())
    assert data["metadata"]["total_results"] == 1
