from pathlib import Path
import shutil

import pytest

from r2morph.core.binary import Binary
from r2morph.relocations.manager import RelocationManager


def test_relocation_manager_space_and_shift(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "reloc_ops"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        functions = bin_obj.get_functions()
        if not functions:
            pytest.skip("No functions found")

        addr = functions[0].get("offset", functions[0].get("addr", 0))
        if not addr:
            pytest.skip("No valid function address")

        # Ensure padding for space calculation
        bin_obj.nop_fill(addr, 8)

        manager = RelocationManager(bin_obj)
        has_space = manager.calculate_space_needed(addr, 4)
        assert isinstance(has_space, bool)

        # Shift a small block and verify relocation registered
        shifted = manager.shift_code_block(addr, 4, 4)
        assert shifted is True
        assert manager.get_new_address(addr) == addr + 4
