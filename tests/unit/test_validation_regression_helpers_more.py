from __future__ import annotations

import hashlib
from pathlib import Path

from r2morph.validation.regression import (
    RegressionResult,
    RegressionTest,
    RegressionTestFramework,
    RegressionTestType,
)
from r2morph.validation.validator import ValidationResult


def test_regression_hash_and_serialization(tmp_path: Path) -> None:
    sample_path = tmp_path / "input.bin"
    sample_path.write_bytes(b"regression")
    expected_hash = hashlib.sha256(sample_path.read_bytes()).hexdigest()

    framework = RegressionTestFramework(baseline_dir=str(tmp_path))
    assert framework._compute_input_hash(sample_path) == expected_hash
    assert framework._compute_input_hash({"key": "value"})

    test = RegressionTest(
        name="t1",
        binary_path=str(sample_path),
        mutations=["nop_insertion"],
        test_cases=[{"args": []}],
        expected_mutations=1,
    )
    test_dict = test.to_dict()
    assert test_dict["name"] == "t1"
    assert test_dict["expected_mutations"] == 1

    validation = ValidationResult(
        passed=True,
        original_output="ok",
        mutated_output="ok",
        original_exitcode=0,
        mutated_exitcode=0,
        errors=[],
        similarity_score=100.0,
    )
    result = RegressionResult(
        test_name="t1",
        passed=True,
        mutations_applied=1,
        expected_mutations=1,
        validation_result=validation,
        timestamp="now",
        errors=[],
    )
    result_dict = result.to_dict()
    assert result_dict["passed"] is True


def test_regression_output_comparison_and_values() -> None:
    framework = RegressionTestFramework()
    expected = {"score": 0.5, "techniques": ["a", "b"], "flag": True}
    actual = {"score": 0.55, "techniques": ["b", "a"], "flag": False, "extra": 1}

    issues = framework._compare_outputs(expected, actual, RegressionTestType.DETECTION_ACCURACY)
    assert any("Missing output keys" in issue for issue in issues) is False
    assert any("Extra output keys" in issue for issue in issues) is True
    assert any("Value mismatch" in issue for issue in issues) is True

    assert framework._values_differ(0.5, 0.55, "score") is False
    assert framework._values_differ(0.5, 0.502, "other") is True
    assert framework._values_differ(["a", "b"], ["b", "a"], "techniques") is False


def test_regression_performance_comparison() -> None:
    framework = RegressionTestFramework()
    baseline = {"runtime_max": 1.0}
    actual = {"runtime": 1.5}
    issues = framework._compare_performance(baseline, actual)
    assert issues
