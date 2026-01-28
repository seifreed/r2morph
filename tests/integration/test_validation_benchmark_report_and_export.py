from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from r2morph.validation.benchmark import (
    AccuracyMetrics,
    BenchmarkCategory,
    BenchmarkResult,
    PerformanceMetrics,
    TestSample,
    TestSeverity,
    ValidationFramework,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_benchmark_summary_report_and_export(tmp_path: Path) -> None:
    sample_path = Path("dataset/elf_x86_64")
    if not sample_path.exists():
        pytest.skip("ELF test binary not available")

    sample = TestSample(
        file_path=str(sample_path),
        sample_hash=_sha256(sample_path),
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=TestSeverity.LOW,
        description="ELF sample",
        source="local_dataset",
    )

    performance = PerformanceMetrics(
        execution_time=0.123,
        memory_usage_mb=1.25,
        cpu_usage_percent=0.0,
        peak_memory_mb=1.5,
        success=True,
        error_message=None,
    )
    accuracy = AccuracyMetrics(
        true_positives=2,
        false_positives=1,
        true_negatives=2,
        false_negatives=0,
        precision=2 / 3,
        recall=1.0,
        f1_score=0.8,
        accuracy=0.8,
    )

    result = BenchmarkResult(
        sample=sample,
        category=BenchmarkCategory.DETECTION,
        performance=performance,
        accuracy=accuracy,
        analysis_result={"packer_detected": None},
        timestamp="2026-01-27 12:00:00",
        r2morph_version="2.0.0-phase2",
    )

    framework = ValidationFramework(test_data_dir=str(tmp_path))
    framework.benchmark_results = [result]

    summary = framework._generate_validation_summary([result])
    assert summary["total_tests"] == 1
    assert summary["successful_tests"] == 1
    assert summary["avg_accuracy"] == pytest.approx(0.8)
    assert summary["execution_time_percentiles"]["p50"] == pytest.approx(0.123)

    report = framework.generate_report()
    assert "R2MORPH VALIDATION REPORT" in report
    assert "OVERALL SUMMARY" in report

    json_path = tmp_path / "benchmark_results.json"
    framework.export_results(str(json_path), "json")
    assert json_path.exists()

    csv_path = tmp_path / "benchmark_results.csv"
    framework.export_results(str(csv_path), "csv")
    assert "sample_path" in csv_path.read_text()


def test_benchmark_accuracy_and_percentiles() -> None:
    framework = ValidationFramework(test_data_dir="dataset")

    expected = {
        "packer_detected": True,
        "vm_protection": False,
        "anti_analysis": False,
        "cfo_detected": True,
        "mba_detected": False,
    }
    actual = {
        "packer_detected": True,
        "vm_protection": True,
        "anti_analysis": False,
        "cfo_detected": False,
        "mba_detected": False,
    }

    metrics = framework._calculate_accuracy_metrics(expected, actual)
    assert metrics.true_positives == 1
    assert metrics.false_positives == 1
    assert metrics.true_negatives == 2
    assert metrics.false_negatives == 1

    assert framework._calculate_percentile([], 95) == 0.0
    assert framework._calculate_percentile([1.0, 2.0, 3.0], 95) == 3.0
