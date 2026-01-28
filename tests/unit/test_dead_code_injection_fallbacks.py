from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass


def test_dead_code_generation_tiny_size(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        pass_obj = DeadCodeInjectionPass(config={"code_complexity": "complex"})
        data = pass_obj._generate_dead_code_for_size(bin_obj, 1, 0)

    assert data is not None
    assert len(data) == 1
