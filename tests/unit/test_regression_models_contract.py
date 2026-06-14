from r2morph.validation import (
    BaselineResult,
    NewRegressionResult,
    RegressionResult,
    RegressionTest,
    RegressionTestType,
    regression_models,
)
from r2morph.validation.validator import ValidationResult


def test_regression_models_are_reexported_from_validation_package() -> None:
    assert BaselineResult is regression_models.BaselineResult
    assert NewRegressionResult is regression_models.NewRegressionResult
    assert RegressionResult is regression_models.RegressionResult
    assert RegressionTest is regression_models.RegressionTest
    assert RegressionTestType is regression_models.RegressionTestType


def test_regression_models_round_trip() -> None:
    baseline = BaselineResult(
        test_id="t1",
        test_type=RegressionTestType.API_COMPATIBILITY,
        input_hash="abc",
        expected_output={"ok": True},
        performance_baseline={"execution_time": 0.1},
        timestamp="now",
        version="1.0",
    )
    assert baseline.test_type.value == "api_compatibility"

    result = RegressionResult(
        test_name="t1",
        passed=True,
        mutations_applied=1,
        expected_mutations=1,
        validation_result=ValidationResult(
            passed=True,
            original_output="ok",
            mutated_output="ok",
            original_exitcode=0,
            mutated_exitcode=0,
            errors=[],
            similarity_score=100.0,
        ),
        timestamp="now",
        errors=[],
    )
    assert result.to_dict()["passed"] is True
