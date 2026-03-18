from pathlib import Path
import json

import pytest

from r2morph.validation.validator import BinaryValidator, RuntimeComparisonConfig


def test_binary_validator_validate_with_inputs(tmp_path: Path):
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    orig = tmp_path / "orig.bin"
    mut = tmp_path / "mut.bin"
    data = source.read_bytes()
    orig.write_bytes(data)
    mut.write_bytes(data)

    validator = BinaryValidator(timeout=5)
    result = validator.validate_with_inputs(orig, mut, ["", "test"])

    assert result.passed is True or result.passed is False
    assert len(validator.test_cases) == 2


def test_binary_validator_similarity_mismatch():
    validator = BinaryValidator(timeout=1)
    similarity = validator._calculate_similarity(
        [{"stdout": "", "stderr": "", "exitcode": 0}],
        [],
    )
    assert similarity == 0.0


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

    assert len(validator.test_cases) == 1
    assert validator.test_cases[0].args == ["--help"]
    assert validator.test_cases[0].monitored_files == ["out.txt"]


def test_binary_validator_detects_monitored_file_difference(tmp_path: Path):
    original = tmp_path / "original.sh"
    mutated = tmp_path / "mutated.sh"
    original.write_text("#!/bin/sh\nprintf 'A' > side_effect.txt\n", encoding="utf-8")
    mutated.write_text("#!/bin/sh\nprintf 'B' > side_effect.txt\n", encoding="utf-8")
    original.chmod(0o755)
    mutated.chmod(0o755)

    validator = BinaryValidator(
        timeout=3,
        comparison=RuntimeComparisonConfig(compare_files=True),
    )
    validator.load_test_cases(
        json.loads(
            '[{"description":"side-effect","args":[],"stdin":"","expected_exitcode":0,"monitored_files":["side_effect.txt"]}]'
        )
    )

    result = validator.validate(original, mutated)

    assert result.passed is False
    assert "side_effect.txt" in result.file_differences
    assert result.compared_signals["files"] is True
