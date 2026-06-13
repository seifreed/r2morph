from r2morph.validation.validator_runtime import (
    RuntimeComparisonConfig,
    ValidationResult,
    ValidationTestCase,
)


def test_runtime_models_round_trip() -> None:
    comparison = RuntimeComparisonConfig(compare_files=True, monitored_files=["out.bin"])
    case = ValidationTestCase(args=["--flag"], stdin="hello", monitored_files=["tmp.log"])
    result = ValidationResult(
        passed=True,
        original_output="ok",
        mutated_output="ok",
        original_exitcode=0,
        mutated_exitcode=0,
        errors=[],
        similarity_score=100.0,
    )

    assert comparison.compare_files is True
    assert case.to_dict()["monitored_files"] == ["tmp.log"]
    assert "PASSED" in str(result)
