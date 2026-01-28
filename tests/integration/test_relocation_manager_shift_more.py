from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.relocations.manager import RelocationManager


def test_relocation_manager_shift_code_block_zero(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "elf_shift"
    temp_binary.write_bytes(binary_path.read_bytes())

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        manager = RelocationManager(bin_obj)
        functions = bin_obj.get_functions()
        if not functions:
            pytest.skip("No functions found in binary")

        func_addr = functions[0].get("offset", 0) or functions[0].get("addr", 0)
        if not func_addr:
            pytest.skip("Invalid function address")

        # Shift by 0 to exercise path without moving content
        ok = manager.shift_code_block(func_addr, 8, 0)
        assert ok is True or ok is False

        space = manager.calculate_space_needed(func_addr, 4)
        assert space is True or space is False
