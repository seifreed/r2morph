"""Contracts for validation result helpers."""

from r2morph.validation.validator_results import build_validation_result, calculate_similarity
from r2morph.validation.validator_runtime import RuntimeComparisonConfig, ValidationTestCase


def test_calculate_similarity_respects_enabled_signals() -> None:
    comparison = RuntimeComparisonConfig(
        compare_exitcode=True,
        compare_stdout=True,
        compare_stderr=False,
        compare_files=False,
    )

    similarity = calculate_similarity(
        [
            {"exitcode": 0, "stdout": "a", "stderr": ""},
            {"exitcode": 1, "stdout": "b", "stderr": ""},
        ],
        [
            {"exitcode": 0, "stdout": "a", "stderr": ""},
            {"exitcode": 9, "stdout": "x", "stderr": ""},
        ],
        comparison,
    )

    assert similarity == 50.0


def test_build_validation_result_serializes_runtime_details() -> None:
    comparison = RuntimeComparisonConfig(
        compare_exitcode=True,
        compare_stdout=True,
        compare_stderr=True,
        compare_files=True,
        normalize_whitespace=True,
    )
    test_case = ValidationTestCase(
        args=["--help"],
        stdin="input",
        env={"A": "1"},
        expected_exitcode=0,
        description="help",
        working_dir="/tmp",
        monitored_files=["out.txt"],
    )

    result = build_validation_result(
        all_outputs_match=True,
        errors=[],
        original_outputs=[{"stdout": "out\n", "stderr": "err\n", "exitcode": 0, "files": {"out.txt": "aa"}}],
        mutated_outputs=[{"stdout": "out\n", "stderr": "err\n", "exitcode": 0, "files": {"out.txt": "aa"}}],
        comparison=comparison,
        file_differences={},
        runtime_details=[
            {
                "description": "help",
                "args": ["--help"],
                "working_dir": "/tmp",
                "original_exitcode": 0,
                "mutated_exitcode": 0,
                "stdout_match": True,
                "stderr_match": True,
                "files_compared": ["out.txt"],
            }
        ],
        test_cases=[test_case],
    )

    assert result.passed is True
    assert result.similarity_score == 100.0
    assert result.compared_signals["files"] is True
    assert result.runtime_details[0]["description"] == "help"
    assert result.test_cases[0]["description"] == "help"
    assert "original_stdout_sha256" in result.output_hashes
