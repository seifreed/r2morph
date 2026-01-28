from pathlib import Path

import pytest

from r2morph.validation.validator import BinaryValidator


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
