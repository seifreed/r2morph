from pathlib import Path
import shutil

import pytest

from r2morph.platform.elf_handler import ELFHandler


def test_elf_handler_find_code_cave(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "elf_code_cave"
    shutil.copy(binary_path, temp_binary)

    handler = ELFHandler(temp_binary)
    cave = handler.find_code_cave(min_size=16)
    assert cave is None or isinstance(cave, int)
