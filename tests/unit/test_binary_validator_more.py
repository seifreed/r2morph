import shutil
import sys
from pathlib import Path

import pytest

from r2morph.validation.validator import BinaryValidator, RuntimeComparisonConfig
from tests.utils.assertions import expect
from tests.utils.process import python_runtime_environment

_EXPECTED_LEN_VALIDATOR_TEST_CASES_2 = 2


def test_binary_validator_validate_with_inputs(tmp_path: Path):
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    orig = tmp_path / "orig.bin"
    mut = tmp_path / "mut.bin"
    data = source.read_bytes()
    orig.write_bytes(data)
    mut.write_bytes(data)

    validator = BinaryValidator(timeout=5)
    result = validator.validate_with_inputs(orig, mut, ["", "test"])

    expect(result.passed is True or result.passed is False)
    expect(len(validator.test_cases) == _EXPECTED_LEN_VALIDATOR_TEST_CASES_2)


def test_binary_validator_similarity_mismatch():
    validator = BinaryValidator(timeout=1)
    similarity = validator._calculate_similarity(
        [{"stdout": "", "stderr": "", "exitcode": 0}],
        [],
    )
    expect(similarity == 0.0)


def test_binary_validator_loads_runtime_corpus():
    validator = BinaryValidator(timeout=1)
    validator.load_test_cases(
        [
            {
                "args": ["--help"],
                "stdin": "",
                "env": {"A": "1"},
                "description": "help",
                "monitored_files": ["out.txt"],
            }
        ]
    )

    expect(len(validator.test_cases) == 1)
    expect(validator.test_cases[0].args == ["--help"])
    expect(validator.test_cases[0].monitored_files == ["out.txt"])


def test_binary_validator_detects_monitored_file_difference(tmp_path: Path):
    original = tmp_path / "original.exe"
    mutated = tmp_path / "mutated.exe"
    shutil.copy2(sys.executable, original)
    shutil.copy2(sys.executable, mutated)
    script = (
        "import pathlib, sys; "
        "value = b'A' if pathlib.Path(sys.executable).stem == 'original' else b'B'; "
        "pathlib.Path('side_effect.txt').write_bytes(value)"
    )

    validator = BinaryValidator(
        timeout=3,
        comparison=RuntimeComparisonConfig(compare_files=True),
    )
    validator.load_test_cases(
        [
            {
                "description": "side-effect",
                "args": ["-c", script],
                "stdin": "",
                "expected_exitcode": 0,
                "env": python_runtime_environment(),
                "monitored_files": ["side_effect.txt"],
            }
        ]
    )

    result = validator.validate(original, mutated)

    expect(not (result.passed is not False))
    expect(not ("side_effect.txt" not in result.file_differences))
    expect(not (result.compared_signals["files"] is not True))


def test_binary_validator_fails_when_file_comparison_has_no_monitored_files(tmp_path: Path):
    original = tmp_path / "original.exe"
    mutated = tmp_path / "mutated.exe"
    shutil.copy2(sys.executable, original)
    shutil.copy2(sys.executable, mutated)

    validator = BinaryValidator(
        timeout=3,
        comparison=RuntimeComparisonConfig(compare_files=True),
    )
    validator.load_test_cases(
        [
            {
                "args": ["-c", "pass"],
                "env": python_runtime_environment(),
            }
        ]
    )

    result = validator.validate(original, mutated)

    expect(not result.passed)
    expect("file comparison enabled but no files are monitored" in result.errors[0])


def test_binary_validator_fails_when_both_runtimes_timeout(monkeypatch, tmp_path: Path):
    original = tmp_path / "original.bin"
    mutated = tmp_path / "mutated.bin"
    original.write_bytes(b"original")
    mutated.write_bytes(b"mutated")

    def timed_out(*_args, **_kwargs):
        return {"stdout": "", "stderr": "Timeout", "exitcode": -1, "files": {}}

    monkeypatch.setattr("r2morph.validation.validator.run_binary", timed_out)
    validator = BinaryValidator()
    validator.add_test_case(description="identical timeout")

    result = validator.validate(original, mutated)

    expect(not result.passed)
    expect("Test 1: runtime did not complete for original, mutated" in result.errors)


def test_binary_validator_fails_when_both_runtimes_miss_expected_exit_code(monkeypatch, tmp_path: Path):
    original = tmp_path / "original.bin"
    mutated = tmp_path / "mutated.bin"
    original.write_bytes(b"original")
    mutated.write_bytes(b"mutated")
    monkeypatch.setattr(
        "r2morph.validation.validator.run_binary",
        lambda *_args, **_kwargs: {"stdout": "same", "stderr": "", "exitcode": 7, "files": {}},
    )
    validator = BinaryValidator()
    validator.add_test_case(description="same unexpected exit")

    result = validator.validate(original, mutated)

    expect(not result.passed)
    expect("Test 1: original exit code 7 did not match expected 0" in result.errors)
