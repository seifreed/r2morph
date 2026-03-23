"""
Real runtime validation tests using host-compiled binaries.
"""

import importlib.util
import json
import shutil
import subprocess
import sys

import pytest

from r2morph.validation.validator import BinaryValidator, RuntimeComparisonConfig

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

    assert strict_result.passed is False
    assert any("stdout mismatch" in error for error in strict_result.errors)
    assert strict_result.output_hashes["original_stdout_sha256"] != strict_result.output_hashes["mutated_stdout_sha256"]
    assert normalized_result.passed is True
    assert normalized_result.compared_signals["normalize_whitespace"] is True
    assert (
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

    assert result.passed is False
    assert "effect.txt" in result.file_differences
    assert result.runtime_details[0]["files_compared"] == ["effect.txt"]


def test_runtime_validator_detects_exitcode_mismatch_real(exitcode_binary_pair):
    original, mutated = exitcode_binary_pair
    validator = BinaryValidator(timeout=5)
    validator.add_test_case(description="exitcode")

    result = validator.validate(original, mutated)

    assert result.passed is False
    assert any("Exit code mismatch" in error for error in result.errors)
    assert result.runtime_details[0]["original_exitcode"] == 0
    assert result.runtime_details[0]["mutated_exitcode"] == 7


def test_runtime_validator_detects_stderr_mismatch_real(stderr_binary_pair):
    original, mutated = stderr_binary_pair
    validator = BinaryValidator(timeout=5)
    validator.add_test_case(description="stderr")

    result = validator.validate(original, mutated)

    assert result.passed is False
    assert any("stderr mismatch" in error for error in result.errors)
    assert result.output_hashes["original_stderr_sha256"] != result.output_hashes["mutated_stderr_sha256"]


@pytest.mark.xfail(reason="CLI validate output format varies by platform", strict=False)
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

    strict_result = subprocess.run(
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
    normalized_result = subprocess.run(
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

    assert strict_result.returncode == 1
    assert normalized_result.returncode == 0
    assert '"normalize_whitespace": true' in normalized_result.stdout


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

    assert result.passed is False
    assert any("stdout mismatch" in error for error in result.errors)
    assert result.runtime_details[0]["args"] == ["alpha"]
    assert result.runtime_details[0]["working_dir"] == str(workdir)


@pytest.mark.xfail(reason="CLI validate output format varies by platform", strict=False)
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

    result = subprocess.run(
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

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["runtime_details"][0]["working_dir"] == str(workdir)
    assert payload["runtime_details"][0]["args"] == ["alpha"]
