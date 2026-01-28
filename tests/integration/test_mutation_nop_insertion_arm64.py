from pathlib import Path
import shutil

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
        pass_obj = NopInsertionPass(
            config={"max_nops_per_function": 2, "probability": 1.0}
        )
        result = pass_obj.apply(bin_obj)

    assert "mutations_applied" in result
