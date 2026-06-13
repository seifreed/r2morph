from types import SimpleNamespace

from r2morph.validation.manager import ValidationIssue, ValidationOutcome
from r2morph.validation.manager_pass_validation import augment_pass_validation


class _FakeAnnotator:
    def _annotate_mutations_with_symbolic_metadata(self, pass_result, metadata):
        for mutation in pass_result["mutations"]:
            mutation.setdefault("metadata", {})["annotated"] = metadata["symbolic_status"]


class _FakeComparator:
    def _compare_real_binary_regions(self, binary, pass_result, bridge_module):
        return {
            "symbolic_binary_check_performed": True,
            "symbolic_binary_equivalent": True,
            "symbolic_binary_reason": "matched",
        }


class _FakeSymbolicValidator:
    def __init__(self):
        self._binary_comparator = _FakeComparator()
        self._mutation_annotator = _FakeAnnotator()

    def _run_symbolic_precheck(self, binary, pass_result):
        return {
            "symbolic_requested": True,
            "symbolic_status": "checked",
            "symbolic_reason": "ok",
        }


class _FakeAbiValidator:
    def __init__(self, issues):
        self._issues = issues

    def collect_violations(self, binary, pass_result):
        return list(self._issues)


def test_validation_manager_pass_validation_annotates_symbolic_metadata() -> None:
    binary = SimpleNamespace()
    pass_result = {
        "pass_name": "InstructionSubstitution",
        "mutations": [{"start_address": 1, "end_address": 2, "metadata": {}}],
    }
    result = ValidationOutcome(validator_type="symbolic", passed=True, scope="pass")

    augment_pass_validation(
        binary,
        pass_result,
        result,
        _FakeSymbolicValidator(),
        _FakeAbiValidator([]),
        symbolic_mode=True,
        check_abi=False,
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
        binary,
        pass_result,
        result,
        _FakeSymbolicValidator(),
        _FakeAbiValidator([issue]),
        symbolic_mode=False,
        check_abi=True,
    )

    assert result.passed is False
    assert result.issues == [issue]
    assert result.metadata["abi_violations"] == 1
