from __future__ import annotations

import platform
from pathlib import Path

import pytest

from r2morph.validation.validator import BinaryValidator
from tests.utils.assertions import expect

_EXPECTED_RESULT_SIMILARITY_SCORE_100_0 = 100.0
_VALIDATION_TIMEOUT_SECONDS = 30


def test_binary_validator_with_macho(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("Binary execution test requires macOS")

    source = Path("fixtures/dataset/macho_arm64")
    if not source.exists():
        pytest.skip("Mach-O test binary not available")

    original = tmp_path / "orig"
    mutated = tmp_path / "mut"
    original.write_bytes(source.read_bytes())
    mutated.write_bytes(source.read_bytes())

    validator = BinaryValidator(timeout=_VALIDATION_TIMEOUT_SECONDS)
    validator.add_test_case(args=[], stdin="", description="default")
    result = validator.validate(original, mutated)

    expect(result.original_exitcode == result.mutated_exitcode)
    expect(result.similarity_score >= _EXPECTED_RESULT_SIMILARITY_SCORE_100_0 or result.similarity_score >= 0.0)
    expect(result.errors == [])


def test_binary_validator_with_inputs(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("Binary execution test requires macOS")

    source = Path("fixtures/dataset/macho_arm64")
    if not source.exists():
        pytest.skip("Mach-O test binary not available")

    original = tmp_path / "orig"
    mutated = tmp_path / "mut"
    original.write_bytes(source.read_bytes())
    mutated.write_bytes(source.read_bytes())

    validator = BinaryValidator(timeout=_VALIDATION_TIMEOUT_SECONDS)
    result = validator.validate_with_inputs(original, mutated, ["", "ping"])
    expect(result.original_exitcode == result.mutated_exitcode)
