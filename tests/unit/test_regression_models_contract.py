from r2morph.validation import (
    BaselineResult,
    NewRegressionResult,
    RegressionResult,
    RegressionTest,
    RegressionTestType,
    regression_models,
)
from r2morph.validation.validator import ValidationResult
from tests.utils.assertions import expect


def test_regression_models_are_reexported_from_validation_package() -> None:
    expect(not (BaselineResult is not regression_models.BaselineResult))
    expect(not (NewRegressionResult is not regression_models.NewRegressionResult))
    expect(not (RegressionResult is not regression_models.RegressionResult))
    expect(not (RegressionTest is not regression_models.RegressionTest))
    expect(not (RegressionTestType is not regression_models.RegressionTestType))


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
    expect(baseline.test_type.value == "api_compatibility")

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
    expect(not (result.to_dict()["passed"] is not True))
