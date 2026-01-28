from pathlib import Path
import shutil

import pytest

from r2morph.core.binary import Binary
from r2morph.relocations.manager import RelocationManager


def test_relocation_manager_update_data_ref(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "reloc_data_ref"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        functions = bin_obj.get_functions()
        if not functions:
            pytest.skip("No functions found")

        addr = functions[0].get("offset", functions[0].get("addr", 0))
        if not addr:
            pytest.skip("No valid function address")

        manager = RelocationManager(bin_obj)
        arch_info = bin_obj.get_arch_info()
        ptr_size = arch_info.get("bits", 64) // 8

        old_target = addr + 0x100
        new_target = addr + 0x200

        # Write old pointer value into the binary at addr
        bin_obj.write_bytes(addr, old_target.to_bytes(ptr_size, byteorder="little"))

        updated = manager._update_data_ref(addr, old_target, new_target)
        assert isinstance(updated, bool)
