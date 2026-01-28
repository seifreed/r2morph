from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from r2morph.validation.benchmark import (
    BenchmarkCategory,
    TestSample,
    TestSeverity,
    ValidationFramework,
)


def test_validation_benchmark_detection_real(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    sample_path = tmp_path / "bench.bin"
    sample_path.write_bytes(source.read_bytes())
    sample_hash = hashlib.sha256(sample_path.read_bytes()).hexdigest()

    sample = TestSample(
        file_path=str(sample_path),
        sample_hash=sample_hash,
        expected_packer=None,
        expected_vm_protection=False,
        expected_anti_analysis=False,
        expected_cfo=False,
        expected_mba=False,
        severity=TestSeverity.LOW,
        description="bench sample",
        source="tests",
    )

    framework = ValidationFramework(test_data_dir=str(tmp_path))
    framework.test_samples = [sample]

    result = framework.benchmark_detection(sample)
    assert result.performance.success is True
    assert result.accuracy is not None

    summary = framework.run_validation_suite([BenchmarkCategory.DETECTION])
    assert summary["total_tests"] == 1
    assert summary["success_rate"] == 1.0

    report = framework.generate_report()
    assert "R2MORPH VALIDATION REPORT" in report
