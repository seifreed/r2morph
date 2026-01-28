from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.relocations.reference_updater import ReferenceUpdater


def test_reference_updater_find_and_update_paths_real(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "elf_refs"
    temp_binary.write_bytes(binary_path.read_bytes())

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        updater = ReferenceUpdater(bin_obj)

        functions = bin_obj.get_functions()
        if not functions:
            pytest.skip("No functions found in binary")

        target_addr = functions[0].get("offset", 0) or functions[0].get("addr", 0)
        if not target_addr:
            pytest.skip("Invalid function address")

        refs = updater.find_references_to(target_addr)
        assert isinstance(refs, list)

        # Updating to the same address should be a no-op or False, but should not crash
        updated = updater.update_all_references_to(target_addr, target_addr)
        assert isinstance(updated, int)
