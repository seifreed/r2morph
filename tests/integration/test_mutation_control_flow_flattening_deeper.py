from pathlib import Path
import shutil

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass


def _find_jump_instruction(binary: Binary) -> dict | None:
    functions = binary.get_functions()
    for func in functions[:10]:
        addr = func.get("offset", func.get("addr", 0))
        if not addr:
            continue
        insns = binary.get_function_disasm(addr)
        for insn in insns:
            if insn.get("mnemonic") == "jmp" and "0x" in insn.get("disasm", ""):
                if insn.get("size", 0) >= 5:
                    return insn
    return None


def test_control_flow_flattening_obfuscate_jump_and_dead_code(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "cff_deeper"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = ControlFlowFlatteningPass()
        arch, bits = bin_obj.get_arch_family()

        jump_insn = _find_jump_instruction(bin_obj)
        if jump_insn:
            obfuscated = pass_obj._obfuscate_jump(bin_obj, jump_insn, {}, arch, bits)
            assert isinstance(obfuscated, bool)

        # Create a NOP sled and attempt dead-code insert
        functions = bin_obj.get_functions()
        if not functions:
            pytest.skip("No functions found")
        addr = functions[0].get("offset", functions[0].get("addr", 0))
        if not addr:
            pytest.skip("No valid function address")

        bin_obj.nop_fill(addr, 8)
        inserted = pass_obj._insert_dead_code_with_predicate(bin_obj, addr, 8, arch, bits)
        assert isinstance(inserted, bool)
