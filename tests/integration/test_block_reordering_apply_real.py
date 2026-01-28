from pathlib import Path
import random
import shutil

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.block_reordering import BlockReorderingPass


def test_block_reordering_apply_real(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "block_reorder"
    shutil.copy(binary_path, temp_binary)

    # Seed to encourage swap path when sizes match
    random.seed(4)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = BlockReorderingPass(
            config={"probability": 1.0, "max_functions": 2}
        )
        result = pass_obj.apply(bin_obj)

    assert "mutations_applied" in result
    assert "functions_mutated" in result
