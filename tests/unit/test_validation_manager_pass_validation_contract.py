from types import SimpleNamespace

from r2morph.validation.manager import ValidationIssue, ValidationOutcome
from r2morph.validation.manager_pass_validation import PassValidationRequest, augment_pass_validation
from tests._doubles.validation_pass_collaborators import FakeAbiValidator, FakeSymbolicValidator


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

    assert result.passed is True
    assert result.metadata["symbolic_requested"] is True
    assert result.metadata["symbolic_binary_check_performed"] is True
    assert pass_result["mutations"][0]["metadata"]["annotated"] == "real-binary-observables-match"


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

    assert result.passed is False
    assert result.issues == [issue]
    assert result.metadata["abi_violations"] == 1
