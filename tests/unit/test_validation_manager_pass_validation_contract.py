from types import SimpleNamespace

from r2morph.validation.manager import ValidationIssue, ValidationOutcome
from r2morph.validation.manager_pass_validation import PassValidationRequest, augment_pass_validation
from tests._doubles.validation_pass_collaborators import FakeAbiValidator, FakeSymbolicValidator
from tests.utils.assertions import expect


def test_validation_manager_pass_validation_annotates_symbolic_metadata() -> None:
    binary = SimpleNamespace()
    pass_result = {
        "pass_name": "InstructionSubstitution",
        "mutations": [{"start_address": 1, "end_address": 2, "metadata": {}}],
    }
    result = ValidationOutcome(validator_type="symbolic", passed=True, scope="pass")

    augment_pass_validation(
        PassValidationRequest(
            binary=binary,
            pass_result=pass_result,
            result=result,
            symbolic_validator=FakeSymbolicValidator(),
            abi_validator=FakeAbiValidator([]),
            symbolic_mode=True,
            check_abi=False,
        )
    )

    expect(not (result.passed is not True))
    expect(not (result.metadata["symbolic_requested"] is not True))
    expect(not (result.metadata["symbolic_binary_check_performed"] is not True))
    expect(pass_result["mutations"][0]["metadata"]["annotated"] == "real-binary-observables-match")


def test_validation_manager_pass_validation_aggregates_abi_issues() -> None:
    binary = SimpleNamespace()
    pass_result = {"pass_name": "nop", "mutations": []}
    issue = ValidationIssue(validator="abi", message="violation")
    result = ValidationOutcome(validator_type="structural", passed=True, scope="pass")

    augment_pass_validation(
        PassValidationRequest(
            binary=binary,
            pass_result=pass_result,
            result=result,
            symbolic_validator=FakeSymbolicValidator(),
            abi_validator=FakeAbiValidator([issue]),
            symbolic_mode=False,
            check_abi=True,
        )
    )

    expect(not (result.passed is not False))
    expect(result.issues == [issue])
    expect(result.metadata["abi_violations"] == 1)
