from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.utils.assembler import R2Assembler, get_common_opcode


def test_r2assembler_basic_roundtrip(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "asm_sample.bin"
    work_path.write_bytes(source.read_bytes())

    with Binary(work_path) as binary:
        binary.analyze()
        assembler = R2Assembler(binary.r2)
        nop_bytes = assembler.assemble("nop")
        assert nop_bytes in (b"\x90", b"\x1f\x00")
        assert assembler.get_instruction_size("nop") >= 1
        assert assembler.disassemble(nop_bytes).startswith("nop")


def test_common_opcode_lookup() -> None:
    assert get_common_opcode("nop") == b"\x90"
    assert get_common_opcode("ret") == b"\xc3"
    assert get_common_opcode("invalid") is None
