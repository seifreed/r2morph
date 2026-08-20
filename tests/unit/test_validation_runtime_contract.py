from r2morph.validation.validator_runtime import (
    RuntimeComparisonConfig,
    ValidationResult,
    ValidationTestCase,
)
from tests.utils.assertions import expect


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

    expect(not (comparison.compare_files is not True))
    expect(case.to_dict()["monitored_files"] == ["tmp.log"])
    expect(not ("PASSED" not in str(result)))
