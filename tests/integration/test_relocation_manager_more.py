from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.relocations.manager import RelocationManager


def test_relocation_manager_address_mapping_real(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "elf_reloc"
    temp_binary.write_bytes(binary_path.read_bytes())

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        manager = RelocationManager(bin_obj)

        manager.add_relocation(0x1000, 0x2000, 0x20)
        assert manager.get_new_address(0x1000) == 0x2000
        assert manager.get_new_address(0x100f) == 0x200f
        assert manager.get_new_address(0x3000) is None


def test_relocation_manager_calculate_space_needed_real(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "elf_space"
    temp_binary.write_bytes(binary_path.read_bytes())

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze("aaa")
        manager = RelocationManager(bin_obj)

        func_addr = 0
        functions = [f for f in bin_obj.get_functions() if f.get("offset")]
        if functions:
            func_addr = functions[0]["offset"]
        else:
            info = bin_obj.r2.cmdj("ij") or {}
            func_addr = info.get("bin", {}).get("entry", 0) or 0

        if not func_addr:
            sections = bin_obj.get_sections()
            exec_sections = [
                section for section in sections if "x" in str(section.get("perm", ""))
            ]
            if exec_sections:
                func_addr = exec_sections[0].get("vaddr", 0) or 0

        assert func_addr, "Expected a valid address for space calculation"

        # Just ensure this path executes without errors
        result = manager.calculate_space_needed(func_addr, 4)
        assert result is True or result is False
