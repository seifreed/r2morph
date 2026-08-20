"""
Real runtime validation tests using host-compiled binaries.
"""

import importlib.util
import json
import shutil
import sys

import pytest

from r2morph.validation.validator import BinaryValidator, RuntimeComparisonConfig
from tests.utils.assertions import expect
from tests.utils.process import run_command

_EXPECTED_RESULT_RUNTIME_DETAILS_0_MUTATED_EXITCODE_7 = 7


if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)

if shutil.which("gcc") is None:
    pytest.skip("gcc not available for compiling test binaries", allow_module_level=True)


def test_runtime_validator_detects_and_normalizes_whitespace(runtime_binary_pair):
    original, mutated = runtime_binary_pair

    strict_validator = BinaryValidator(timeout=5)
    strict_validator.add_test_case(description="strict")
    strict_result = strict_validator.validate(original, mutated)

    normalized_validator = BinaryValidator(
        timeout=5,
        comparison=RuntimeComparisonConfig(normalize_whitespace=True),
    )
    normalized_validator.add_test_case(description="normalized")
    normalized_result = normalized_validator.validate(original, mutated)

    expect(not (strict_result.passed is not False))
    expect(any("stdout mismatch" in error for error in strict_result.errors))
    expect(
        strict_result.output_hashes["original_stdout_sha256"] != strict_result.output_hashes["mutated_stdout_sha256"]
    )
    expect(not (normalized_result.passed is not True))
    expect(not (normalized_result.compared_signals["normalize_whitespace"] is not True))
    expect(
        normalized_result.output_hashes["normalized_original_stdout_sha256"]
        == normalized_result.output_hashes["normalized_mutated_stdout_sha256"]
    )


def test_runtime_validator_detects_monitored_file_side_effects_real(file_effect_binary_pair):
    original, mutated = file_effect_binary_pair
    validator = BinaryValidator(
        timeout=5,
        comparison=RuntimeComparisonConfig(compare_files=True),
    )
    validator.load_test_cases(
        [
            {
                "description": "file-side-effect",
                "args": [],
                "stdin": "",
                "expected_exitcode": 0,
                "monitored_files": ["effect.txt"],
            }
        ]
    )

    result = validator.validate(original, mutated)

    expect(not (result.passed is not False))
    expect(not ("effect.txt" not in result.file_differences))
    expect(result.runtime_details[0]["files_compared"] == ["effect.txt"])


def test_runtime_validator_detects_exitcode_mismatch_real(exitcode_binary_pair):
    original, mutated = exitcode_binary_pair
    validator = BinaryValidator(timeout=5)
    validator.add_test_case(description="exitcode")

    result = validator.validate(original, mutated)

    expect(not (result.passed is not False))
    expect(any("Exit code mismatch" in error for error in result.errors))
    expect(result.runtime_details[0]["original_exitcode"] == 0)
    expect(result.runtime_details[0]["mutated_exitcode"] == _EXPECTED_RESULT_RUNTIME_DETAILS_0_MUTATED_EXITCODE_7)


def test_runtime_validator_detects_stderr_mismatch_real(stderr_binary_pair):
    original, mutated = stderr_binary_pair
    validator = BinaryValidator(timeout=5)
    validator.add_test_case(description="stderr")

    result = validator.validate(original, mutated)

    expect(not (result.passed is not False))
    expect(any("stderr mismatch" in error for error in result.errors))
    expect(result.output_hashes["original_stderr_sha256"] != result.output_hashes["mutated_stderr_sha256"])


def test_cli_validate_supports_normalize_whitespace(runtime_binary_pair, tmp_path):
    original, mutated = runtime_binary_pair
    corpus = tmp_path / "runtime_corpus.json"
    corpus.write_text(
        json.dumps(
            [
                {
                    "description": "stdout-format",
                    "args": [],
                    "stdin": "",
                    "expected_exitcode": 0,
                }
            ]
        ),
        encoding="utf-8",
    )

    strict_result = run_command(
        [
            sys.executable,
            "-m",
            "r2morph.cli",
            "validate",
            str(original),
            str(mutated),
            "--corpus",
            str(corpus),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    normalized_result = run_command(
        [
            sys.executable,
            "-m",
            "r2morph.cli",
            "validate",
            str(original),
            str(mutated),
            "--corpus",
            str(corpus),
            "--normalize-whitespace",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    expect(strict_result.returncode == 1)
    expect(normalized_result.returncode == 0)
    expect(not ('"normalize_whitespace": true' not in normalized_result.stdout))


def test_runtime_validator_detects_args_env_working_dir_mismatch_real(args_env_binary_pair, tmp_path):
    original, mutated = args_env_binary_pair
    workdir = tmp_path / "exec"
    workdir.mkdir()

    validator = BinaryValidator(timeout=5)
    validator.load_test_cases(
        [
            {
                "description": "args-env-working-dir",
                "args": ["alpha"],
                "stdin": "",
                "env": {"R2MORPH_MODE": "fixture"},
                "expected_exitcode": 0,
                "working_dir": str(workdir),
            }
        ]
    )

    result = validator.validate(original, mutated)

    expect(not (result.passed is not False))
    expect(any("stdout mismatch" in error for error in result.errors))
    expect(result.runtime_details[0]["args"] == ["alpha"])
    expect(result.runtime_details[0]["working_dir"] == str(workdir))


def test_cli_validate_supports_args_env_working_dir_corpus_real(args_env_binary_pair, tmp_path):
    original, mutated = args_env_binary_pair
    workdir = tmp_path / "exec"
    workdir.mkdir()
    corpus = tmp_path / "runtime_args_env.json"
    corpus.write_text(
        json.dumps(
            [
                {
                    "description": "args-env-working-dir",
                    "args": ["alpha"],
                    "stdin": "",
                    "env": {"R2MORPH_MODE": "fixture"},
                    "expected_exitcode": 0,
                    "working_dir": str(workdir),
                }
            ]
        ),
        encoding="utf-8",
    )

    result = run_command(
        [
            sys.executable,
            "-m",
            "r2morph.cli",
            "validate",
            str(original),
            str(mutated),
            "--corpus",
            str(corpus),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    expect(result.returncode == 1)
    payload = json.loads(result.stdout)
    expect(payload["runtime_details"][0]["working_dir"] == str(workdir))
    expect(payload["runtime_details"][0]["args"] == ["alpha"])
