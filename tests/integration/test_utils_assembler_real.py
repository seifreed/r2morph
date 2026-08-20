from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.utils.assembler import R2Assembler, get_common_opcode
from tests.utils.assertions import expect


def test_r2assembler_basic_roundtrip(tmp_path: Path) -> None:
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "asm_sample.bin"
    work_path.write_bytes(source.read_bytes())

    with Binary(work_path) as binary:
        binary.analyze()
        assembler = R2Assembler(binary.r2)
        nop_bytes = assembler.assemble("nop")
        expect(not (nop_bytes not in (b"\x90", b"\x1f\x00")))
        expect(not (assembler.get_instruction_size("nop") < 1))
        expect(assembler.disassemble(nop_bytes).startswith("nop"))


def test_common_opcode_lookup() -> None:
    expect(get_common_opcode("nop") == b"\x90")
    expect(get_common_opcode("ret") == b"\xc3")
    expect(not (get_common_opcode("invalid") is not None))
