import hashlib
import json

from r2morph.validation.benchmark import (
    AccuracyMetrics,
    BenchmarkCategory,
    BenchmarkResult,
    PerformanceMetrics,
    TestSample,
    TestSeverity,
    ValidationFramework,
)


def _make_sample(file_path: str, sample_hash: str) -> TestSample:
    return TestSample(
        file_path=file_path,
        sample_hash=sample_hash,
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=TestSeverity.LOW,
        description="test sample",
        source="unit-test",
    )


def test_testsample_hash_verification_and_existence(tmp_path):
    sample_path = tmp_path / "sample.bin"
    payload = b"r2morph-benchmark"
    sample_path.write_bytes(payload)

    sha = hashlib.sha256(payload).hexdigest()
    sample = _make_sample(str(sample_path), sha)
    assert sample.file_exists is True
    assert sample.verify_hash() is True

    bad_sample = _make_sample(str(sample_path), "0" * 64)
    assert bad_sample.verify_hash() is False


def test_measure_performance_success_and_failure(tmp_path):
    framework = ValidationFramework(test_data_dir=str(tmp_path))

    metrics, result = framework._measure_performance(lambda x: x + 1, 4)
    assert metrics.success is True
    assert result == 5
    assert metrics.execution_time >= 0.0

    metrics_fail, result_fail = framework._measure_performance(lambda: 1 / 0)
    assert metrics_fail.success is False
    assert result_fail is None
    assert metrics_fail.error_message


def test_accuracy_metrics_and_summary_generation(tmp_path):
    sample_path = tmp_path / "sample.bin"
    payload = b"r2morph-summary"
    sample_path.write_bytes(payload)
    sha = hashlib.sha256(payload).hexdigest()

    framework = ValidationFramework(test_data_dir=str(tmp_path))
    expected = {
        "packer_detected": False,
        "vm_protection": True,
        "anti_analysis": False,
        "cfo_detected": True,
        "mba_detected": False,
    }
    actual = {
        "packer_detected": False,
        "vm_protection": True,
        "anti_analysis": True,
        "cfo_detected": True,
        "mba_detected": False,
    }
    accuracy = framework._calculate_accuracy_metrics(expected, actual)
    assert isinstance(accuracy, AccuracyMetrics)
    assert accuracy.true_positives == 2
    assert accuracy.false_positives == 1
    assert accuracy.false_negatives == 0

    sample = _make_sample(str(sample_path), sha)
    performance = PerformanceMetrics(
        execution_time=1.25,
        memory_usage_mb=2.0,
        cpu_usage_percent=0.0,
        peak_memory_mb=2.0,
        success=True,
        error_message=None,
    )
    result = BenchmarkResult(
        sample=sample,
        category=BenchmarkCategory.DETECTION,
        performance=performance,
        accuracy=accuracy,
        analysis_result={"ok": True},
        timestamp="2025-01-01 00:00:00",
        r2morph_version="2.0.0-phase2",
    )

    summary = framework._generate_validation_summary([result])
    assert summary["total_tests"] == 1
    assert summary["successful_tests"] == 1
    assert summary["avg_accuracy"] >= 0.0
    assert summary["execution_time_percentiles"]["p95"] >= 1.25


def test_export_and_report_outputs(tmp_path):
    sample_path = tmp_path / "sample.bin"
    payload = b"r2morph-export"
    sample_path.write_bytes(payload)
    sha = hashlib.sha256(payload).hexdigest()

    framework = ValidationFramework(test_data_dir=str(tmp_path))
    sample = _make_sample(str(sample_path), sha)
    performance = PerformanceMetrics(
        execution_time=0.5,
        memory_usage_mb=1.0,
        cpu_usage_percent=0.0,
        peak_memory_mb=1.0,
        success=True,
        error_message=None,
    )
    accuracy = AccuracyMetrics(
        true_positives=1,
        false_positives=0,
        true_negatives=4,
        false_negatives=0,
        precision=1.0,
        recall=1.0,
        f1_score=1.0,
        accuracy=1.0,
    )
    result = BenchmarkResult(
        sample=sample,
        category=BenchmarkCategory.DETECTION,
        performance=performance,
        accuracy=accuracy,
        analysis_result={"ok": True},
        timestamp="2025-01-01 00:00:00",
        r2morph_version="2.0.0-phase2",
    )
    framework.benchmark_results = [result]

    json_path = tmp_path / "results.json"
    csv_path = tmp_path / "results.csv"

    framework.export_results(str(json_path), "json")
    framework.export_results(str(csv_path), "csv")

    export_data = json.loads(json_path.read_text())
    assert export_data["metadata"]["total_results"] == 1
    assert export_data["summary"]["total_tests"] == 1
    assert "results" in export_data

    csv_text = csv_path.read_text()
    assert "sample_path" in csv_text

    report = framework.generate_report()
    assert "R2MORPH VALIDATION REPORT" in report
