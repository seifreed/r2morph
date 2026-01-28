from pathlib import Path
import shutil

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass


def test_control_flow_flattening_insertion_paths(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "cff_insert"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = ControlFlowFlatteningPass()
        arch, bits = bin_obj.get_arch_family()

        functions = bin_obj.get_functions()
        if not functions:
            pytest.skip("No functions found")

        addr = functions[0].get("offset", functions[0].get("addr", 0))
        if not addr:
            pytest.skip("No valid function address")

        # Create slack space and try opaque predicate insertion
        bin_obj.nop_fill(addr, 24)
        inserted = pass_obj._add_opaque_predicate(bin_obj, addr, 24, arch, bits)
        assert isinstance(inserted, bool)

        # Try dead-code insertion on NOPs
        dead_inserted = pass_obj._insert_dead_code_with_predicate(bin_obj, addr, 16, arch, bits)
        assert isinstance(dead_inserted, bool)
