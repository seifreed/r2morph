from pathlib import Path

from r2morph.validation.benchmark import (
    ValidationFramework,
    BenchmarkResult,
    BenchmarkCategory,
    TestSeverity,
    TestSample,
    PerformanceMetrics,
    AccuracyMetrics,
)


def _make_sample(path: Path, severity: TestSeverity) -> TestSample:
    return TestSample(
        file_path=str(path),
        sample_hash="dummy",
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=severity,
        description="unit sample",
        source="unit",
    )


def _make_result(path: Path, category: BenchmarkCategory, severity: TestSeverity, success: bool) -> BenchmarkResult:
    return BenchmarkResult(
        sample=_make_sample(path, severity),
        category=category,
        performance=PerformanceMetrics(
            execution_time=1.2,
            memory_usage_mb=12.0,
            cpu_usage_percent=5.0,
            peak_memory_mb=15.0,
            success=success,
        ),
        accuracy=AccuracyMetrics(
            true_positives=1,
            false_positives=0,
            true_negatives=1,
            false_negatives=0,
            precision=1.0,
            recall=1.0,
            f1_score=1.0,
            accuracy=1.0,
        ),
        analysis_result={},
        timestamp="now",
        r2morph_version="unit",
    )


def test_benchmark_summary_and_report_generation(tmp_path: Path):
    framework = ValidationFramework(test_data_dir=str(tmp_path))
    dummy = tmp_path / "sample.bin"
    dummy.write_bytes(b"sample")

    framework.benchmark_results = [
        _make_result(dummy, BenchmarkCategory.DETECTION, TestSeverity.LOW, True),
        _make_result(dummy, BenchmarkCategory.FULL_PIPELINE, TestSeverity.CRITICAL, False),
    ]

    summary = framework._generate_validation_summary(framework.benchmark_results)
    assert summary["total_tests"] == 2
    assert summary["successful_tests"] == 1
    assert "detection" in summary["categories"]

    report = framework.generate_report()
    assert "R2MORPH VALIDATION REPORT" in report
    assert "OVERALL SUMMARY" in report
