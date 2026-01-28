from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.nop_insertion import NopInsertionPass


def test_nop_insertion_helpers():
    pass_obj = NopInsertionPass()
    pass_obj._init_nop_equivalents()
    assert "x86" in pass_obj.NOP_EQUIVALENTS
    assert pass_obj.NOP_EQUIVALENTS["x86"]


def test_nop_generate_jmp_dead_code():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        # Force 32-bit mode for deterministic short JMP sizes.
        bin_obj.r2.cmd("e asm.bits=32")
        bin_obj.r2.cmd("e asm.arch=x86")
        pass_obj = NopInsertionPass()
        data = pass_obj._generate_jmp_dead_code(3, 32, bin_obj, 0)
        unsupported = pass_obj._generate_jmp_dead_code(2, 32, bin_obj, 0)

    assert unsupported is None
    if data is not None:
        assert len(data) == 3
