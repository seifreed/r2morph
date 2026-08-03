"""Unit tests for movsxd (sign-extend dword->qword) region virtualization.

``movsxd rax, dword [mem]`` sign-extends a 32-bit source into a 64-bit destination;
r2 types it under the mov type. A plain-memory source lowers to the ``movx`` load
handler, a scaled-index source to ``movxidx``, and a register source to ``movxreg``;
each emits a native ``movsxd`` to perform the sign extension. These pin the decode,
region acceptance, and the emitted sign-extension on the real lifter - no r2, no mocks.
"""

from __future__ import annotations

import random
from typing import Any

from r2morph.mutations.code_virtualization_region import _classify, extract_region
from r2morph.mutations.code_virtualization_region_codegen import _movx_reg_handler_asm
from r2morph.mutations.code_virtualization_region_handlers import _movx_load_asm


def _insn(addr: int, size: int, opcode: str) -> dict[str, Any]:
    # r2 reports movsxd under the mov type, with the mnemonic in the opcode text.
    return {"addr": addr, "size": size, "type": "mov", "opcode": opcode}


def test_classify_movsxd_plain_memory_lowers_to_movx_sign_extend_dword() -> None:
    # dst rax(0), base rbx(3), disp 0; ext "s", src_size 32, dst_width 64.
    assert _classify(_insn(0x1000, 4, "movsxd rax, dword [rbx]")) == ["movx", "s", 32, 64, 0, 3, 0]


def test_classify_movsxd_indexed_memory_lowers_to_movxidx_sign_extend_dword() -> None:
    # dst rax(0), base rbx(3), index rcx(1), shift log2(4)=2, disp 0.
    item = _classify(_insn(0x1000, 4, "movsxd rax, dword [rbx + rcx*4]"))
    assert item == ["movxidx", "s", 32, 64, 0, 3, 1, 2, 0]


def test_classify_movsxd_register_source_lowers_to_movxreg_sign_extend_dword() -> None:
    # dst rax(0), src ecx(1); movsxd's register form sign-extends the low dword.
    assert _classify(_insn(0x1000, 3, "movsxd rax, ecx")) == ["movxreg", "s", 32, 64, 0, 1]


def test_extract_region_accepts_movsxd_indexed_dword_load() -> None:
    # The scaled-index movsxd lowers to a vmovxidx micro-op carrying (ext, src_size,
    # dst_width) = sign-extend dword->qword; its presence proves the region was accepted.
    region = extract_region(_movsxd_region_instructions(), random.Random(1))
    assert region is not None
    assert ("vmovxidx", "s", 32, 64, 3, 1, 2, 0) in [tuple(item) for item in region.instructions]


def test_extract_region_accepts_movsxd_plain_dword_load() -> None:
    region = extract_region(_movsxd_region_instructions(), random.Random(1))
    assert region is not None
    assert ("vmovx", "s", 32, 64, 3, 0) in [tuple(item) for item in region.instructions]


def test_movsxd_memory_load_emits_native_sign_extend_dword() -> None:
    # The shared load helper the movx/movxidx handlers emit sign-extends via movsxd.
    assert _movx_load_asm("s", 32, 64) == "  movsxd rax, dword ptr [r10]\n"


def test_movsxd_register_handler_emits_native_sign_extend_dword() -> None:
    assert "movsxd r10, eax" in _movx_reg_handler_asm("movxreg_s_32_64", 0x5A)


def _movsxd_region_instructions() -> list[dict[str, Any]]:
    """A straight-line region: two movsxd dword loads (indexed then plain) and a ret."""
    return [
        _insn(0x1000, 4, "movsxd rax, dword [rbx + rcx*4]"),
        _insn(0x1004, 3, "movsxd rax, dword [rbx]"),
        {"addr": 0x1007, "size": 1, "type": "ret", "opcode": "ret"},
    ]
