import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.nop_insertion import NopInsertionPass


def test_nop_insertion_arm64_path(tmp_path: Path):
    binary_path = Path("dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    temp_binary = tmp_path / "macho_arm64_nop"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0})
        result = pass_obj.apply(bin_obj)

    assert "mutations_applied" in result


def test_nop_insertion_arm64_does_not_record_encoding_identical_rewrites(tmp_path: Path):
    """ARM64 `mov w0, #0` is an alias of `movz w0, #0` and assembles to the same
    bytes; rewriting one as the other changes nothing, so it must not be recorded
    or counted as a mutation."""
    binary_path = Path("dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    temp_binary = tmp_path / "macho_arm64_noop"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0})
        result = pass_obj.apply(bin_obj)

    noop_records = [r for r in pass_obj._records if r.original_bytes == r.mutated_bytes]
    assert noop_records == []
    assert result["mutations_applied"] == len(pass_obj._records)
