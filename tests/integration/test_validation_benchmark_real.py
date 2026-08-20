from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from r2morph.validation.benchmark import ValidationFramework
from r2morph.validation.benchmark_types import (
    BenchmarkCategory,
    TestSample,
    TestSeverity,
)
from tests.utils.assertions import expect


def test_validation_benchmark_detection_real(tmp_path: Path) -> None:
    source = Path("fixtures/dataset/elf_x86_64")
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
    expect(not (result.performance.success is not True))
    expect(result.accuracy is not None)

    summary = framework.run_validation_suite([BenchmarkCategory.DETECTION])
    expect(summary["total_tests"] == 1)
    expect(summary["success_rate"] == 1.0)

    report = framework.generate_report()
    expect(not ("R2MORPH VALIDATION REPORT" not in report))
