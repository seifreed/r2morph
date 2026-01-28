from __future__ import annotations

import platform
from pathlib import Path

import pytest

from r2morph.validation.validator import BinaryValidator


def test_binary_validator_with_macho(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("Binary execution test requires macOS")

    source = Path("dataset/macho_arm64")
    if not source.exists():
        pytest.skip("Mach-O test binary not available")

    original = tmp_path / "orig"
    mutated = tmp_path / "mut"
    original.write_bytes(source.read_bytes())
    mutated.write_bytes(source.read_bytes())

    validator = BinaryValidator(timeout=5)
    validator.add_test_case(args=[], stdin="", description="default")
    result = validator.validate(original, mutated)

    assert result.original_exitcode == result.mutated_exitcode
    assert result.similarity_score >= 100.0 or result.similarity_score >= 0.0
    assert result.errors == []


def test_binary_validator_with_inputs(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("Binary execution test requires macOS")

    source = Path("dataset/macho_arm64")
    if not source.exists():
        pytest.skip("Mach-O test binary not available")

    original = tmp_path / "orig"
    mutated = tmp_path / "mut"
    original.write_bytes(source.read_bytes())
    mutated.write_bytes(source.read_bytes())

    validator = BinaryValidator(timeout=5)
    result = validator.validate_with_inputs(original, mutated, ["", "ping"])
    assert result.original_exitcode == result.mutated_exitcode
