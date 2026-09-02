"""Unit tests for movsxd (sign-extend dword->qword) region virtualization.

``movsxd rax, dword [mem]`` sign-extends a 32-bit source into a 64-bit destination;
r2 types it under the mov type. A plain-memory source lowers to the ``movx`` load
handler, a scaled-index source to ``movxidx``, and a register source to ``movxreg``;
each emits a native ``movsxd`` to perform the sign extension. These pin the decode,
region acceptance, and the emitted sign-extension on the real lifter - no r2, no mocks.
"""

from __future__ import annotations

from typing import Any

from r2morph.core import randomness
from r2morph.mutations.code_virtualization import _decode_run_item
from r2morph.mutations.code_virtualization_engine import build_vm_blob, build_vm_scheme
from r2morph.mutations.code_virtualization_engine_handlers import EngineHandlerGenerator
from r2morph.mutations.code_virtualization_engine_models import VirtualizedAddress, VirtualizedMemOp
from r2morph.mutations.code_virtualization_region import extract_region
from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_control_handlers import _movx_reg_handler_asm
from r2morph.mutations.code_virtualization_region_memory_handlers import _movx_load_asm
from tests.utils.assertions import expect


def _insn(addr: int, size: int, opcode: str) -> dict[str, Any]:
    # r2 reports movsxd under the mov type, with the mnemonic in the opcode text.
    return {"addr": addr, "size": size, "type": "mov", "opcode": opcode}


def test_classify_movsxd_plain_memory_lowers_to_movx_sign_extend_dword() -> None:
    # dst rax(0), base rbx(3), disp 0; ext "s", src_size 32, dst_width 64.
    expect(_classify(_insn(4096, 4, "movsxd rax, dword [rbx]")) == ["movx", "s", 32, 64, 0, 3, 0])


def test_classify_movsxd_indexed_memory_lowers_to_movxidx_sign_extend_dword() -> None:
    # dst rax(0), base rbx(3), index rcx(1), shift log2(4)=2, disp 0.
    item = _classify(_insn(0x1000, 4, "movsxd rax, dword [rbx + rcx*4]"))
    expect(item == ["movxidx", "s", 32, 64, 0, 3, 1, 2, 0])


def test_classify_movsxd_register_source_lowers_to_movxreg_sign_extend_dword() -> None:
    # dst rax(0), src ecx(1); movsxd's register form sign-extends the low dword.
    expect(_classify(_insn(4096, 3, "movsxd rax, ecx")) == ["movxreg", "s", 32, 64, 0, 1])


def test_extract_region_accepts_movsxd_indexed_dword_load() -> None:
    # The scaled-index movsxd lowers to a vmovxidx micro-op carrying (ext, src_size,
    # dst_width) = sign-extend dword->qword; its presence proves the region was accepted.
    region = extract_region(_movsxd_region_instructions(), randomness.Random(1))
    expect(region is not None)
    expect(not (("vmovxidx", "s", 32, 64, 3, 1, 2, 0) not in [tuple(item) for item in region.instructions]))


def test_extract_region_accepts_movsxd_plain_dword_load() -> None:
    region = extract_region(_movsxd_region_instructions(), randomness.Random(1))
    expect(region is not None)
    expect(not (("vmovx", "s", 32, 64, 3, 0) not in [tuple(item) for item in region.instructions]))


def test_movsxd_memory_load_emits_native_sign_extend_dword() -> None:
    # The shared load helper the movx/movxidx handlers emit sign-extends via movsxd.
    expect(_movx_load_asm("s", 32, 64) == "  movsxd rax, dword ptr [r10]\n")


def test_movsxd_register_handler_emits_native_sign_extend_dword() -> None:
    expect(not ("movsxd r10, eax" not in _movx_reg_handler_asm("movxreg_s_32_64", 0x5A)))


def test_linear_engine_decodes_movsxd_plain_memory_as_dword_load() -> None:
    item = _decode_run_item("movsxd rax, dword ptr [rbx-4]")
    expect(
        isinstance(item, VirtualizedMemOp)
        and (item.kind, item.reg_index, item.base_index, item.disp, item.width) == ("movsxd", 0, 3, -4, 64)
    )


def test_linear_engine_decodes_movsxd_indexed_memory_as_dword_load() -> None:
    item = _decode_run_item("movsxd rax, dword ptr [rbx+rcx*4+8]")
    expect(
        isinstance(item, VirtualizedMemOp)
        and (item.kind, item.reg_index, item.base_index, item.index_index, item.scale, item.disp, item.width)
        == ("movsxdidx", 0, 3, 1, 2, 8, 64)
    )


def test_linear_engine_movsxd_handler_reads_dword_and_sign_extends() -> None:
    body = EngineHandlerGenerator._extend_memory_body("movsxd", 64)
    expect(body == "  movsxd rax, dword ptr [r10]\n  mov qword ptr [rsp + r8*8], rax\n")


def test_linear_engine_assembles_movsxd_memory_operations() -> None:
    scheme = build_vm_scheme(randomness.Random(20260903))
    blob = build_vm_blob(
        [
            VirtualizedMemOp("movsxd", 0, VirtualizedAddress(1, -4), 64),
            VirtualizedMemOp("movsxdidx", 0, VirtualizedAddress(1, 8, 2, 2), 64),
        ],
        0x500000,
        0x401000,
        scheme,
    )
    expect(blob is not None)


def _movsxd_region_instructions() -> list[dict[str, Any]]:
    """A straight-line region: two movsxd dword loads (indexed then plain) and a ret."""
    return [
        _insn(0x1000, 4, "movsxd rax, dword [rbx + rcx*4]"),
        _insn(0x1004, 3, "movsxd rax, dword [rbx]"),
        {"addr": 0x1007, "size": 1, "type": "ret", "opcode": "ret"},
    ]
