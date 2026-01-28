import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.analysis.cfg import BasicBlock
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass


def test_control_flow_flattening_arm64_internal_helpers(tmp_path: Path):
    if platform.system() != "Darwin":
        pytest.skip("macOS-only test")

    binary_path = Path("dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    temp_binary = tmp_path / "macho_arm64_mut"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        arch_family, bits = bin_obj.get_arch_family()
        if arch_family != "arm":
            pytest.skip("ARM64 binary required")

        funcs = bin_obj.get_functions()
        if not funcs:
            pytest.skip("No functions found")

        func_addr = funcs[0].get("offset", funcs[0].get("addr", 0))
        instructions = bin_obj.get_function_disasm(func_addr)
        if not instructions:
            pytest.skip("No instructions found")

        addr = instructions[0].get("addr", 0)
        if addr == 0:
            pytest.skip("Invalid instruction address")

        pass_obj = ControlFlowFlatteningPass()
        ok_pred = pass_obj._add_opaque_predicate(bin_obj, addr, 16, arch_family, bits)
        ok_dead = pass_obj._insert_dead_code_with_predicate(bin_obj, addr, 16, arch_family, bits)

        blocks = [BasicBlock(address=0x1000, size=4), BasicBlock(address=0x2000, size=4)]
        dispatcher = pass_obj._generate_dispatcher(bin_obj, blocks)

    assert isinstance(ok_pred, bool)
    assert isinstance(ok_dead, bool)
    assert isinstance(dispatcher, list)
