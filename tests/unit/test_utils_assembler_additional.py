from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.utils.assembler import R2Assembler, get_common_opcode


def test_get_common_opcode_lookup():
    assert get_common_opcode("nop") == b"\x90"
    assert get_common_opcode("xor eax, eax") is not None
    assert get_common_opcode("unknown") is None


def test_r2assembler_disassemble_roundtrip():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        asm = R2Assembler(bin_obj.r2)
        encoded = asm.assemble("nop")
        assert encoded == b"\x90"
        decoded = asm.disassemble(encoded)
        assert decoded is not None
