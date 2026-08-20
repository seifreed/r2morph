from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.validation.regression import (
    RegressionTestFramework,
    RegressionTestType,
)
from tests.utils.assertions import expect


def test_regression_api_baseline_roundtrip(tmp_path: Path) -> None:
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))
    baseline = framework.create_api_compatibility_baseline("api_smoke")
    expect(not (baseline.test_id not in framework.baselines))

    result = framework.run_regression_test("api_smoke")
    expect(not (result.passed is not True))
    expect(not (result.actual_output["binary_import"] is not True))


def test_regression_detection_baseline_and_hash_mismatch(tmp_path: Path) -> None:
    binary_path = Path("fixtures/dataset/elf_x86_64")
    alt_binary = Path("fixtures/dataset/macho_arm64")
    if not binary_path.exists() or not alt_binary.exists():
        pytest.skip("Dataset binaries not available")

    framework = RegressionTestFramework(baseline_dir=str(tmp_path))
    framework.create_detection_baseline("detect_smoke", str(binary_path))

    stable = framework.run_regression_test("detect_smoke", str(binary_path))
    expect(not (stable.passed is not True))

    mismatch = framework.run_regression_test("detect_smoke", str(alt_binary))
    expect(not (mismatch.passed is not False))
    expect(any("hash mismatch" in issue for issue in mismatch.issues))


def test_regression_compare_helpers(tmp_path: Path) -> None:
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))

    issues = framework._compare_outputs(
        {"a": 1, "b": 2},
        {"a": 2, "c": 3},
        test_type=RegressionTestType.DETECTION_ACCURACY,
    )
    expect(any("Missing output keys" in issue for issue in issues))
    expect(any("Extra output keys" in issue for issue in issues))

    expect(not (framework._values_differ(1.0, 1.05, "confidence_score") is not False))
    expect(not (framework._values_differ(1.0, 1.2, "confidence_score") is not True))
    expect(not (framework._values_differ(["a", "b"], ["b", "a"], "obfuscation_techniques") is not False))
    expect(not (framework._values_differ(["a"], ["a", "b"], "list") is not True))

    perf_issues = framework._compare_performance(
        {"execution_time_max": 0.1},
        {"execution_time": 0.2},
    )
    expect(perf_issues)
