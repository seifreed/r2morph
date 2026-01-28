from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.block_reordering import BlockReorderingPass


def test_block_reordering_apply_real(tmp_path: Path) -> None:
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "sample.bin"
    work_path.write_bytes(binary_path.read_bytes())

    with Binary(work_path, writable=True) as binary:
        binary.analyze()
        pass_obj = BlockReorderingPass(
            config={"probability": 1.0, "max_functions": 1, "preserve_fallthrough": True}
        )
        result = pass_obj.apply(binary)

    assert result["total_functions"] >= 0
    assert result["functions_processed"] <= 1
    assert "mutations_applied" in result
