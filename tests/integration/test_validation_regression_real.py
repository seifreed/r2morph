from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.validation.regression import RegressionTestFramework, RegressionTestType


def test_regression_detection_baseline_and_run(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    baseline_dir = tmp_path / "baselines"
    framework = RegressionTestFramework(baseline_dir=str(baseline_dir))

    test_id = "detect_elf"
    baseline = framework.create_detection_baseline(test_id, str(source))
    assert baseline.test_type == RegressionTestType.DETECTION_ACCURACY
    assert (baseline_dir / f"{test_id}.json").exists()

    result = framework.run_regression_test(test_id, str(source))
    assert result.passed is True
    assert result.issues == []


def test_regression_api_baseline_and_run(tmp_path: Path) -> None:
    baseline_dir = tmp_path / "baselines"
    framework = RegressionTestFramework(baseline_dir=str(baseline_dir))

    test_id = "api_check"
    baseline = framework.create_api_compatibility_baseline(test_id)
    assert baseline.test_type == RegressionTestType.API_COMPATIBILITY

    result = framework.run_regression_test(test_id)
    assert result.passed is True
