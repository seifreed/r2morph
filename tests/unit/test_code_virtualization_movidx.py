"""Unit tests for scaled-index mov load/store lowering (``loadidx``/``storeidx``).

Plain ``mov reg, [base+index*scale+disp]`` and its store form lower to the
``vloadidx``/``vstoreidx`` micro-ops, so scaled-index array access virtualizes
without a native memory instruction. These pin the decode, the item schema, and
the lowering on the real lifter (no mocks, no binary).
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization import _decode_run_item
from r2morph.mutations.code_virtualization_engine_models import VirtualizedMemOp
from r2morph.mutations.code_virtualization_region import _lower_arith_to_microops
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_memory_decoders import _decode_memory_mov_indexed
from r2morph.mutations.code_virtualization_region_models import _op_key
from tests.utils.assertions import expect

_EXPECTED_ITEM_SIZE_VSTOREIDX_1_2_2_0_64_9 = 9


def test_decode_indexed_mov_load_returns_loadidx_with_reg_slot_and_width() -> None:
    # mov eax, [rcx + rdx*4]: dst rax(0), base rcx(1), index rdx(2), shift log2(4)=2.
    expect(_decode_memory_mov_indexed("mov eax, [rcx + rdx*4]") == ("loadidx", 0, 1, 2, 2, 0, 32))


def test_linear_engine_indexed_mov_load_returns_memory_item() -> None:
    item = _decode_run_item("mov eax, [rcx + rdx*4]")
    expect(
        isinstance(item, VirtualizedMemOp)
        and (item.kind, item.reg_index, item.base_index, item.index_index, item.scale, item.disp, item.width)
        == ("loadidx", 0, 1, 2, 2, 0, 32)
    )


def test_decode_indexed_mov_store_returns_storeidx() -> None:
    # mov [rcx + rdx*8 + 16], rax: source rax(0), base rcx(1), index rdx(2), shift 3.
    expect(_decode_memory_mov_indexed("mov [rcx + rdx*8 + 16], rax") == ("storeidx", 0, 1, 2, 3, 16, 64))


def test_linear_engine_indexed_mov_store_returns_memory_item() -> None:
    item = _decode_run_item("mov [rcx + rdx*8 + 16], rax")
    expect(
        isinstance(item, VirtualizedMemOp)
        and (item.kind, item.reg_index, item.base_index, item.index_index, item.scale, item.disp, item.width)
        == ("storeidx", 0, 1, 2, 3, 16, 64)
    )


def test_decode_no_base_indexed_mov_load_returns_loadidxnb() -> None:
    expect(_decode_memory_mov_indexed("mov eax, [rdx*4 + 16]") == ("loadidxnb", 0, 2, 2, 16, 32))


def test_linear_engine_no_base_indexed_mov_load_is_rejected() -> None:
    expect(_decode_run_item("mov eax, [rdx*4 + 16]") is None)


def test_decode_no_base_indexed_mov_store_returns_storeidxnb() -> None:
    expect(_decode_memory_mov_indexed("mov [rdx*8 + 16], rax") == ("storeidxnb", 0, 2, 3, 16, 64))


def test_decode_indexed_mov_rejects_non_indexed_base_disp() -> None:
    # A plain base+disp load is not this decoder's job (the base+disp decoder owns it).
    expect(not (_decode_memory_mov_indexed("mov eax, [rcx + 4]") is not None))


def test_decode_indexed_mov_rejects_rip_relative() -> None:
    expect(not (_decode_memory_mov_indexed("mov eax, [rip + rdx*4]") is not None))


def test_decode_indexed_mov_accepts_byte_register() -> None:
    expect(_decode_memory_mov_indexed("mov al, [rcx + rdx*4]") == ("loadidx", 0, 1, 2, 2, 0, 8))


def test_vstoreidx_item_size_matches_vloadidx() -> None:
    # opcode + (unused) reg + base + index slots + scale shift + 4-byte disp.
    expect(_item_size(("vstoreidx", 1, 2, 2, 0, 64)) == _EXPECTED_ITEM_SIZE_VSTOREIDX_1_2_2_0_64_9)


def test_vstoreidx_op_key_carries_width() -> None:
    expect(_op_key(("vstoreidx", 1, 2, 3, 16, 64)) == "vstoreidx_64")


def test_loadidx_lowers_to_vloadidx_then_vpop() -> None:
    lowered = _lower_arith_to_microops([["loadidx", 0, 1, 2, 2, 0, 32]])
    expect([item[0] for item in lowered] == ["vloadidx", "vpop"])


def test_storeidx_lowers_to_vpush_then_vstoreidx() -> None:
    lowered = _lower_arith_to_microops([["storeidx", 0, 1, 2, 3, 16, 64]])
    expect([item[0] for item in lowered] == ["vpush", "vstoreidx"])


def test_loadidxnb_lowers_to_vloadidxnb_then_vpop() -> None:
    lowered = _lower_arith_to_microops([["loadidxnb", 0, 2, 2, 16, 32]])
    expect([item[0] for item in lowered] == ["vloadidxnb", "vpop"])


def test_storeidxnb_lowers_to_vpush_then_vstoreidxnb() -> None:
    lowered = _lower_arith_to_microops([["storeidxnb", 0, 2, 3, 16, 64]])
    expect([item[0] for item in lowered] == ["vpush", "vstoreidxnb"])
