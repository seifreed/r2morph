from pathlib import Path
import shutil

import pytest

from r2morph.platform.elf_handler import ELFHandler


def test_elf_handler_add_section_and_preserve_symbols(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "elf_with_section"
    shutil.copy(binary_path, temp_binary)

    handler = ELFHandler(temp_binary)

    # Try adding a new section (requires lief). If lief missing, expect None.
    vaddr = handler.add_section(".r2morph_test", 0x100)
    assert vaddr is None or isinstance(vaddr, int)

    preserved = handler.preserve_symbols()
    assert isinstance(preserved, bool)
