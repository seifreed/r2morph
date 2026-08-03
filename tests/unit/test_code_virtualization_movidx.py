"""Unit tests for scaled-index mov load/store lowering (``loadidx``/``storeidx``).

Plain ``mov reg, [base+index*scale+disp]`` and its store form lower to the
``vloadidx``/``vstoreidx`` micro-ops, so scaled-index array access virtualizes
without a native memory instruction. These pin the decode, the item schema, and
the lowering on the real lifter (no mocks, no binary).
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region import _lower_arith_to_microops
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_decoders import _decode_memory_mov_indexed
from r2morph.mutations.code_virtualization_region_models import _op_key


def test_decode_indexed_mov_load_returns_loadidx_with_reg_slot_and_width() -> None:
    # mov eax, [rcx + rdx*4]: dst rax(0), base rcx(1), index rdx(2), shift log2(4)=2.
    assert _decode_memory_mov_indexed("mov eax, [rcx + rdx*4]") == ("loadidx", 0, 1, 2, 2, 0, 32)


def test_decode_indexed_mov_store_returns_storeidx() -> None:
    # mov [rcx + rdx*8 + 16], rax: source rax(0), base rcx(1), index rdx(2), shift 3.
    assert _decode_memory_mov_indexed("mov [rcx + rdx*8 + 16], rax") == ("storeidx", 0, 1, 2, 3, 16, 64)


def test_decode_indexed_mov_rejects_non_indexed_base_disp() -> None:
    # A plain base+disp load is not this decoder's job (the base+disp decoder owns it).
    assert _decode_memory_mov_indexed("mov eax, [rcx + 4]") is None


def test_decode_indexed_mov_rejects_rip_relative() -> None:
    assert _decode_memory_mov_indexed("mov eax, [rip + rdx*4]") is None


def test_decode_indexed_mov_rejects_byte_register() -> None:
    # An 8-bit destination has no 32/64-bit slot mapping here, so it stays native.
    assert _decode_memory_mov_indexed("mov al, [rcx + rdx*4]") is None


def test_vstoreidx_item_size_matches_vloadidx() -> None:
    # opcode + (unused) reg + base + index slots + scale shift + 4-byte disp.
    assert _item_size(("vstoreidx", 1, 2, 2, 0, 64)) == 9


def test_vstoreidx_op_key_carries_width() -> None:
    assert _op_key(("vstoreidx", 1, 2, 3, 16, 64)) == "vstoreidx_64"


def test_loadidx_lowers_to_vloadidx_then_vpop() -> None:
    lowered = _lower_arith_to_microops([["loadidx", 0, 1, 2, 2, 0, 32]])
    assert [item[0] for item in lowered] == ["vloadidx", "vpop"]


def test_storeidx_lowers_to_vpush_then_vstoreidx() -> None:
    lowered = _lower_arith_to_microops([["storeidx", 0, 1, 2, 3, 16, 64]])
    assert [item[0] for item in lowered] == ["vpush", "vstoreidx"]
