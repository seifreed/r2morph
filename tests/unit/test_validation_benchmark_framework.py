import hashlib
from pathlib import Path

from r2morph.validation.benchmark import (
    ValidationFramework,
    TestSample,
    TestSeverity,
    BenchmarkCategory,
    BenchmarkResult,
)


def test_test_sample_hash_verification(tmp_path):
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
        description="hash verification",
        source="unit_test",
    )

    assert sample.file_exists is True
    assert sample.verify_hash() is True


def test_validation_framework_metrics_and_exports(tmp_path):
    framework = ValidationFramework(test_data_dir=str(tmp_path))

    performance, result = framework._measure_performance(lambda: {"ok": True})
    assert performance.success is True
    assert result["ok"] is True

    expected = {
        "packer_detected": None,
        "vm_protection": False,
        "anti_analysis": False,
        "cfo_detected": False,
        "mba_detected": False,
    }
    actual = {
        "packer_detected": None,
        "vm_protection": False,
        "anti_analysis": False,
        "cfo_detected": False,
        "mba_detected": False,
    }
    accuracy = framework._calculate_accuracy_metrics(expected, actual)

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
        severity=TestSeverity.MEDIUM,
        description="benchmark",
        source="unit_test",
    )

    benchmark = BenchmarkResult(
        sample=sample,
        category=BenchmarkCategory.DETECTION,
        performance=performance,
        accuracy=accuracy,
        analysis_result={"ok": True},
        timestamp="2026-01-27 00:00:00",
        r2morph_version="2.0.0-phase2",
    )

    framework.benchmark_results.append(benchmark)

    summary = framework._generate_validation_summary(framework.benchmark_results)
    assert summary["total_tests"] == 1

    json_path = tmp_path / "results.json"
    csv_path = tmp_path / "results.csv"

    framework.export_results(str(json_path), format="json")
    framework.export_results(str(csv_path), format="csv")

    assert json_path.exists()
    assert csv_path.exists()


def test_benchmark_detection_and_pipeline(tmp_path):
    binary_path = Path("dataset/elf_x86_64")
    sample_hash = hashlib.sha256(binary_path.read_bytes()).hexdigest()

    sample = TestSample(
        file_path=str(binary_path),
        sample_hash=sample_hash,
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=TestSeverity.LOW,
        description="dataset elf",
        source="dataset",
    )

    framework = ValidationFramework(test_data_dir=str(tmp_path))

    detection_result = framework.benchmark_detection(sample)
    assert detection_result.performance is not None

    full_result = framework.benchmark_full_pipeline(sample)
    assert full_result.performance is not None
