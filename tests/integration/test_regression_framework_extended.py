from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.validation.regression import (
    RegressionResult,
    RegressionTestFramework,
    RegressionTester,
    RegressionTestType,
)
from r2morph.validation.validator import ValidationResult


def test_regression_api_baseline_roundtrip(tmp_path: Path) -> None:
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))
    baseline = framework.create_api_compatibility_baseline("api_smoke")
    assert baseline.test_id in framework.baselines

    result = framework.run_regression_test("api_smoke")
    assert result.passed is True
    assert result.actual_output["binary_import"] is True


def test_regression_detection_baseline_and_hash_mismatch(tmp_path: Path) -> None:
    binary_path = Path("dataset/elf_x86_64")
    alt_binary = Path("dataset/macho_arm64")
    if not binary_path.exists() or not alt_binary.exists():
        pytest.skip("Dataset binaries not available")

    framework = RegressionTestFramework(baseline_dir=str(tmp_path))
    framework.create_detection_baseline("detect_smoke", str(binary_path))

    stable = framework.run_regression_test("detect_smoke", str(binary_path))
    assert stable.passed is True

    mismatch = framework.run_regression_test("detect_smoke", str(alt_binary))
    assert mismatch.passed is False
    assert any("hash mismatch" in issue for issue in mismatch.issues)


def test_regression_compare_helpers(tmp_path: Path) -> None:
    framework = RegressionTestFramework(baseline_dir=str(tmp_path))

    issues = framework._compare_outputs(
        {"a": 1, "b": 2},
        {"a": 2, "c": 3},
        test_type=RegressionTestType.DETECTION_ACCURACY,
    )
    assert any("Missing output keys" in issue for issue in issues)
    assert any("Extra output keys" in issue for issue in issues)

    assert framework._values_differ(1.0, 1.05, "confidence_score") is False
    assert framework._values_differ(1.0, 1.2, "confidence_score") is True
    assert framework._values_differ(["a", "b"], ["b", "a"], "obfuscation_techniques") is False
    assert framework._values_differ(["a"], ["a", "b"], "list") is True

    perf_issues = framework._compare_performance(
        {"execution_time_max": 0.1},
        {"execution_time": 0.2},
    )
    assert perf_issues


def test_regression_tester_mutation_lookup_and_results(tmp_path: Path) -> None:
    tester = RegressionTester(test_dir=tmp_path)

    mutation = tester._get_mutation_pass("nop")
    assert mutation is not None

    with pytest.raises(ValueError):
        tester._get_mutation_pass("unknown-mutation")

    validation = ValidationResult(
        passed=True,
        original_output="",
        mutated_output="",
        original_exitcode=0,
        mutated_exitcode=0,
        errors=[],
        similarity_score=1.0,
    )

    tester.results = [
        RegressionResult(
            test_name="smoke",
            passed=True,
            mutations_applied=0,
            expected_mutations=None,
            validation_result=validation,
            timestamp="2026-01-27T12:00:00",
            errors=[],
        )
    ]

    output_path = tmp_path / "results.json"
    tester.save_results(output_file=output_path)
    assert output_path.exists()
