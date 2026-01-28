import hashlib
from pathlib import Path

from r2morph.validation.benchmark import (
    BenchmarkCategory,
    TestSample,
    TestSeverity,
    ValidationFramework,
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def test_validation_benchmark_deeper_paths(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    sample_hash = _sha256(binary_path)

    framework = ValidationFramework(test_data_dir=str(tmp_path))
    framework.test_samples = []

    sample = TestSample(
        file_path=str(binary_path),
        sample_hash=sample_hash,
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=TestSeverity.LOW,
        description="Local ELF sample",
        source="unit_test",
    )

    framework.add_test_sample(sample)

    detection_result = framework.benchmark_detection(sample)
    assert detection_result.category == BenchmarkCategory.DETECTION
    assert isinstance(detection_result.analysis_result, dict)

    devirt_result = framework.benchmark_devirtualization(sample)
    assert devirt_result.category == BenchmarkCategory.DEVIRTUALIZATION

    pipeline_result = framework.benchmark_full_pipeline(sample)
    assert pipeline_result.category == BenchmarkCategory.FULL_PIPELINE

    framework.benchmark_results.extend([detection_result, devirt_result, pipeline_result])

    summary = framework.run_validation_suite([BenchmarkCategory.DETECTION])
    assert summary["total_tests"] >= 1

    json_path = tmp_path / "benchmark_results.json"
    csv_path = tmp_path / "benchmark_results.csv"

    framework.export_results(str(json_path), format="json")
    framework.export_results(str(csv_path), format="csv")

    assert json_path.exists()
    assert csv_path.exists()

    report = framework.generate_report()
    assert "VALIDATION REPORT" in report
