"""Region VM micro-op lowering: flag-dead arithmetic becomes virtual-stack primitives.

These pin the structural contract that a flag-dead reg-reg/immediate arithmetic op no
longer maps 1:1 to a native handler but lowers to a push/push/fold/pop micro-op
sequence over the interpreter's private operand stack, with the stack primitives
shared across distinct native ops. Semantic parity through the lowered path is covered
by the Unicorn exit-code fixtures in the integration suite (the flag-dead add/sub/bool
fixtures now route through these micro-ops).
"""

from __future__ import annotations

import struct

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_region import extract_region
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_handlers import _VSP_OFFSET
from r2morph.mutations.code_virtualization_region_nesting import build_nested_region_blob
from tests.utils.assertions import expect

_EXPECTED_ITEM_SIZE_VLEAIDXNB_6_3_8_64_8 = 8
_EXPECTED_ITEM_SIZE_VLEAIDX_5_6_3_8_64_9 = 9
_EXPECTED_ITEM_SIZE_VLEARIP_0X401000_64_6 = 6
_EXPECTED_ITEM_SIZE_VLEA_5_8_64_7 = 7
_EXPECTED_ITEM_SIZE_VLOADIDX_5_6_3_8_64_9 = 9
_EXPECTED_ITEM_SIZE_VLOADRIP_0_64_6 = 6
_EXPECTED_ITEM_SIZE_VLOAD_5_8_64_7 = 7
_EXPECTED_ITEM_SIZE_VMOVXIDX_S_16_64_5_6_1_8_9 = 9
_EXPECTED_ITEM_SIZE_VMOVX_Z_8_64_5_8_7 = 7
_EXPECTED_ITEM_SIZE_VPOP_3_2 = 2
_EXPECTED_ITEM_SIZE_VPUSHI_5_32_5 = 5
_EXPECTED_ITEM_SIZE_VPUSHI_5_64_9 = 9
_EXPECTED_ITEM_SIZE_VPUSH_3_2 = 2
_EXPECTED_ITEM_SIZE_VSHIFT_SHL_3_64_2 = 2
_EXPECTED_ITEM_SIZE_VSTORERIP_0_64_6 = 6
_EXPECTED_ITEM_SIZE_VSTORE_5_8_64_7 = 7
_EXPECTED_KINDS_COUNT_VBINOP_2 = 2
_EXPECTED_KINDS_COUNT_VBINOP_2_2 = 2
_EXPECTED_KINDS_COUNT_VPOP_2 = 2
_EXPECTED_KINDS_COUNT_VPOP_2_2 = 2
_EXPECTED_KINDS_COUNT_VPUSH_2 = 2


def _insn(addr: int, size: int, itype: str, opcode: str, **extra: object) -> dict[str, object]:
    return {"addr": addr, "size": size, "type": itype, "opcode": opcode, **extra}


def _flag_dead_arith_region(second: dict[str, object]) -> list[tuple[object, ...]]:
    """Region items for `add eax,ebx` then a second arith op, both flag-dead.

    A trailing `cmp`+`jne` overwrites the flags the two arithmetic ops set before any
    branch reads them, so flag-liveness marks both as flag-dead (lowered to micro-ops).
    """
    insns = [
        _insn(0x1000, 3, "add", "add eax, ebx"),
        second,
        _insn(0x1006, 3, "cmp", "cmp eax, edx"),
        _insn(0x1009, 2, "cjmp", "jne 0x1000", jump=0x1000, fail=0x100B),
        _insn(0x100B, 1, "ret", "ret"),
    ]
    region = extract_region(insns)
    expect(region is not None)
    return list(region.instructions)


def test_flag_dead_reg_reg_arith_lowers_to_shared_microop_sequence() -> None:
    items = _flag_dead_arith_region(_insn(0x1003, 3, "xor", "xor eax, ecx"))
    kinds = [item[0] for item in items]
    # The 1:1 arithmetic handler is gone; each op became push/push/binop/pop (the
    # trailing cmp also lowers now, so only the per-op fold/pop counts are asserted).
    expect("opmba" not in kinds and "op_add" not in kinds)
    expect(
        kinds.count("vbinop") == _EXPECTED_KINDS_COUNT_VBINOP_2 and kinds.count("vpop") == _EXPECTED_KINDS_COUNT_VPOP_2
    )
    # add and xor share the SAME vpush/vpop primitives; only the fold differs.
    binops = {item[1] for item in items if item[0] == "vbinop"}
    expect(binops == {"add", "xor"})


def test_flag_dead_immediate_arith_lowers_with_vpushi() -> None:
    items = _flag_dead_arith_region(_insn(0x1003, 3, "add", "add eax, 5"))
    kinds = [item[0] for item in items]
    # The immediate form pushes the constant via vpushi, sharing vpush/vpop/vbinop.
    expect(not ("vpushi" not in kinds))
    expect(
        kinds.count("vbinop") == _EXPECTED_KINDS_COUNT_VBINOP_2_2
        and kinds.count("vpop") == _EXPECTED_KINDS_COUNT_VPOP_2_2
    )


def test_flag_live_arith_lowers_to_flag_synthesizing_microop() -> None:
    # `add` whose flags a following `jns` reads lowers to the same push/push/fold/pop
    # shape, but the fold is vbinopsynth (computes the result AND synthesizes the
    # readable flags) rather than the flag-dead vbinop - the single opsynth handler is
    # gone, and the stack primitives are shared with the flag-dead form.
    insns = [
        _insn(0x1000, 3, "add", "add eax, ebx"),
        _insn(0x1003, 2, "cjmp", "jns 0x1000", jump=0x1000, fail=0x1005),
        _insn(0x1005, 1, "ret", "ret"),
    ]
    region = extract_region(insns)
    expect(region is not None)
    kinds = [item[0] for item in region.instructions]
    expect("opsynth" not in kinds)
    expect(kinds.count("vbinopsynth") == 1)
    expect(kinds.count("vpush") == _EXPECTED_KINDS_COUNT_VPUSH_2 and kinds.count("vpop") == 1)


def test_shift_lowers_to_shared_push_shift_pop_sequence() -> None:
    # A native shl/shr/sar reg,imm lowers to vpush(slot)/vshift/vpop(slot), reusing the
    # same stack primitives as the arithmetic folds instead of a dedicated shift handler.
    insns = [
        _insn(0x1000, 3, "shl", "shl eax, 4"),
        _insn(0x1003, 2, "cjmp", "jne 0x1000", jump=0x1000, fail=0x1005),
        _insn(0x1005, 1, "ret", "ret"),
    ]
    region = extract_region(insns)
    expect(region is not None)
    kinds = [item[0] for item in region.instructions]
    # No standalone shift handler survives; the shift is a shared push/shift/pop.
    expect("shift" not in kinds and "shl" not in {k.split("_")[0] for k in region.op_keys})
    expect(kinds.count("vshift") == 1)
    expect(kinds.count("vpush") == 1 and kinds.count("vpop") == 1)


def test_nested_prologue_zeroes_the_vstack_pointer() -> None:
    # The virtual stack pointer must be zeroed in the nested vm_entry too, not just
    # the single-layer one: peeled flag-dead arith folds through the vstack in the
    # nested layers, and a non-zero initial pointer would make the first vpush write
    # to a wild frame offset. (Unicorn zero-fills mapped pages, so an exit-code test
    # cannot catch this; the instruction must be present in the emitted interpreter.)
    insns = [
        _insn(0x1000, 3, "add", "add eax, ebx"),
        _insn(0x1003, 3, "xor", "xor eax, ecx"),
        _insn(0x1006, 3, "cmp", "cmp eax, edx"),
        _insn(0x1009, 2, "cjmp", "jne 0x1000", jump=0x1000, fail=0x100B),
        _insn(0x100B, 1, "ret", "ret"),
    ]
    region = extract_region(insns, randomness.Random(1))
    expect(region is not None)
    blob = build_nested_region_blob(region, 0x401000, randomness.Random(7), depth=2)
    expect(blob is not None)
    # mov qword ptr [rsp + _VSP_OFFSET], 0  (REX.W C7 /0, SIB base=rsp, disp32, imm32=0)
    vsp_zero = b"\x48\xc7\x84\x24" + struct.pack("<i", _VSP_OFFSET) + b"\x00\x00\x00\x00"
    expect(not (vsp_zero not in blob))


def test_micro_op_item_sizes_match_the_handler_advances() -> None:
    # The encoded byte length of each micro-op item must equal its handler's rsi
    # advance, or the virtual instruction pointer desyncs. vpush/vpop carry one slot
    # byte; vpushi carries only its width-sized immediate; vbinop carries nothing.
    expect(_item_size(("vshift", "shl", 3, 64)) == _EXPECTED_ITEM_SIZE_VSHIFT_SHL_3_64_2)
    expect(_item_size(("vpush", 3)) == _EXPECTED_ITEM_SIZE_VPUSH_3_2)
    expect(_item_size(("vpop", 3)) == _EXPECTED_ITEM_SIZE_VPOP_3_2)
    expect(_item_size(("vpushi", 5, 32)) == _EXPECTED_ITEM_SIZE_VPUSHI_5_32_5)
    expect(_item_size(("vpushi", 5, 64)) == _EXPECTED_ITEM_SIZE_VPUSHI_5_64_9)
    expect(_item_size(("vbinop", "add", 64)) == 1)
    expect(_item_size(("vbinopsynth", "add", 64)) == 1)
    expect(_item_size(("vload", 5, -8, 64)) == _EXPECTED_ITEM_SIZE_VLOAD_5_8_64_7)
    expect(_item_size(("vstore", 5, -8, 64)) == _EXPECTED_ITEM_SIZE_VSTORE_5_8_64_7)
    expect(_item_size(("vloadidx", 5, 6, 3, -8, 64)) == _EXPECTED_ITEM_SIZE_VLOADIDX_5_6_3_8_64_9)
    expect(_item_size(("vcmpsynth", "cmp", 64)) == 1)
    expect(_item_size(("vcmpsynth", "test", 32)) == 1)


def _memory_region(access: dict[str, object]) -> list[tuple[object, ...]]:
    """Region items for a single base+disp memory instruction then a terminator."""
    region = extract_region([access, _insn(0x1010, 1, "ret", "ret")])
    expect(region is not None)
    return list(region.instructions)


def test_base_disp_load_lowers_to_vload_then_vpop() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 5, "mov", "mov rax, qword [rsp - 8]"))]
    # mov reg,[base+disp] loads onto the stack, then pops into the destination slot.
    expect("load" not in kinds)
    expect(kinds[:2] == ["vload", "vpop"])


def test_base_disp_store_lowers_to_vpush_then_vstore() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 5, "mov", "mov qword [rsp - 0x10], rax"))]
    # mov [base+disp],reg pushes the register then stores the stack top.
    expect("store" not in kinds)
    expect(kinds[:2] == ["vpush", "vstore"])


def test_mem_source_arith_lowers_to_vpush_vload_vbinopsynth_vpop() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 3, "add", "add rax, qword [rsp - 8]"))]
    # <op> reg,[base+disp] pushes reg, loads the memory operand, folds them with the
    # flag-synthesizing stack fold (mem arith is always flag-live today), pops to reg.
    expect("opmem" not in kinds)
    expect(kinds[:4] == ["vpush", "vload", "vbinopsynth", "vpop"])


def test_indexed_mem_source_arith_lowers_to_vpush_vloadidx_vbinopsynth_vpop() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 4, "add", "add rax, qword [rax + rcx*8]"))]
    # <op> reg,[base+index*scale+disp] pushes reg, loads the indexed memory operand
    # via the scaled-index prologue, folds with flag synthesis, pops back to reg.
    expect("opmemidx" not in kinds)
    expect(kinds[:4] == ["vpush", "vloadidx", "vbinopsynth", "vpop"])


def test_read_modify_write_lowers_to_vload_vpush_vbinopsynth_vstore() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 4, "add", "add qword [rax - 8], rcx"))]
    # <op> [base+disp],reg loads the memory value, pushes the register, folds them,
    # and stores the result back to the same address (recomputed, base+disp is fixed).
    expect("opmemdst" not in kinds)
    expect(kinds[:4] == ["vload", "vpush", "vbinopsynth", "vstore"])


def _compare_region(compare: dict[str, object]) -> list[str]:
    """Region item kinds for a compare that drives a conditional branch."""
    insns = [
        compare,
        _insn(0x1010, 2, "cjmp", "jne 0x1000", jump=0x1000, fail=0x1012),
        _insn(0x1012, 1, "ret", "ret"),
    ]
    region = extract_region(insns)
    expect(region is not None)
    return [item[0] for item in region.instructions]


def test_cmp_reg_reg_lowers_to_vpush_vpush_vcmpsynth() -> None:
    kinds = _compare_region(_insn(0x1000, 3, "cmp", "cmp rax, rbx"))
    # The single cmp handler is gone; both operands are pushed and the flags are
    # synthesized off the stack with no stored result.
    expect("cmp" not in kinds)
    expect(kinds[:3] == ["vpush", "vpush", "vcmpsynth"])


def test_cmp_reg_imm_lowers_with_vpushi() -> None:
    kinds = _compare_region(_insn(0x1000, 4, "cmp", "cmp rax, 5"))
    expect("cmp" not in kinds)
    expect(kinds[:3] == ["vpush", "vpushi", "vcmpsynth"])


def test_test_reg_reg_lowers_to_vcmpsynth() -> None:
    kinds = _compare_region(_insn(0x1000, 3, "acmp", "test rax, rbx"))
    expect("test" not in kinds)
    expect(kinds[:3] == ["vpush", "vpush", "vcmpsynth"])


def test_cmp_with_memory_operand_lowers_to_vpush_vload_vcmpsynth() -> None:
    kinds = _compare_region(_insn(0x1000, 4, "cmp", "cmp rax, qword [rsp - 8]"))
    # cmp reg,[base+disp] reuses the base+disp vload primitive before the compare.
    expect("cmpmem" not in kinds)
    expect(kinds[:3] == ["vpush", "vload", "vcmpsynth"])


def test_cmp_with_rip_relative_operand_lowers_to_vpush_vloadrip_vcmpsynth() -> None:
    kinds = _compare_region(_insn(0x1000, 7, "cmp", "cmp rax, qword [rip + 0x2000]"))
    # cmp reg,[rip+disp] reuses the rip-relative vloadrip primitive before the compare.
    expect("cmpriprel" not in kinds)
    expect(kinds[:3] == ["vpush", "vloadrip", "vcmpsynth"])


def test_rip_relative_load_lowers_to_vloadrip() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 7, "mov", "mov rax, qword [rip + 0x2000]"))]
    # mov reg,[rip+disp] pushes the global via vloadrip then pops it into the register.
    expect("riprel_load" not in kinds)
    expect(kinds[:2] == ["vloadrip", "vpop"])


def test_rip_relative_store_lowers_to_vpush_vstorerip() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 7, "mov", "mov qword [rip + 0x2000], rax"))]
    expect("riprel_store" not in kinds)
    expect(kinds[:2] == ["vpush", "vstorerip"])


def test_rip_relative_arith_lowers_with_vloadrip_and_vbinopsynth() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 7, "add", "add rax, qword [rip + 0x2000]"))]
    # <op> reg,[rip+disp] pushes reg, loads the global, folds them with the
    # flag-synthesizing stack fold, pops to reg.
    expect("opriprel" not in kinds)
    expect(kinds[:4] == ["vpush", "vloadrip", "vbinopsynth", "vpop"])


def test_rip_relative_rmw_lowers_to_vloadrip_vbinopsynth_vstorerip() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 7, "add", "add qword [rip + 0x2000], rax"))]
    # <op> [rip+disp],reg loads the global, pushes reg, folds, stores the result back.
    expect("opmemdstrip" not in kinds)
    expect(kinds[:4] == ["vloadrip", "vpush", "vbinopsynth", "vstorerip"])


def test_rip_relative_micro_op_item_sizes() -> None:
    # opcode + (unused) reg slot + 4-byte bytecode-relative offset.
    expect(_item_size(("vloadrip", 0, 64)) == _EXPECTED_ITEM_SIZE_VLOADRIP_0_64_6)
    expect(_item_size(("vstorerip", 0, 64)) == _EXPECTED_ITEM_SIZE_VSTORERIP_0_64_6)


def test_lea_base_disp_lowers_to_vlea_then_vpop() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 4, "lea", "lea rax, [rdi + 0x10]"))]
    # lea reg,[base+disp] computes the effective address onto the stack (no deref),
    # then pops it into the destination slot; no dedicated lea handler survives.
    expect("lea" not in kinds)
    expect(kinds[:2] == ["vlea", "vpop"])


def test_lea_rip_relative_lowers_to_vlearip_then_vpop() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 7, "lea", "lea rax, [rip + 0x2000]"))]
    expect("learip" not in kinds)
    expect(kinds[:2] == ["vlearip", "vpop"])


def test_lea_scaled_index_lowers_to_vleaidx_then_vpop() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 5, "lea", "lea rax, [rdi + rcx*4 + 8]"))]
    expect("leaidx" not in kinds)
    expect(kinds[:2] == ["vleaidx", "vpop"])


def test_lea_no_base_scaled_index_lowers_to_vleaidxnb_then_vpop() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 8, "lea", "lea rax, [rcx*8 + 0x20]"))]
    expect("leaidxnb" not in kinds)
    expect(kinds[:2] == ["vleaidxnb", "vpop"])


def test_lea_micro_op_item_sizes_match_the_handler_advances() -> None:
    # A lea micro-op must encode exactly as many bytes as its handler's rsi advance,
    # or the virtual instruction pointer desyncs. The address goes on the vstack, so
    # the register field is an unused placeholder that still occupies its byte.
    expect(_item_size(("vlea", 5, -8, 64)) == _EXPECTED_ITEM_SIZE_VLEA_5_8_64_7)
    expect(_item_size(("vlearip", 4198400, 64)) == _EXPECTED_ITEM_SIZE_VLEARIP_0X401000_64_6)
    expect(_item_size(("vleaidx", 5, 6, 3, -8, 64)) == _EXPECTED_ITEM_SIZE_VLEAIDX_5_6_3_8_64_9)
    expect(_item_size(("vleaidxnb", 6, 3, -8, 64)) == _EXPECTED_ITEM_SIZE_VLEAIDXNB_6_3_8_64_8)


def test_movzx_from_memory_lowers_to_vmovx_then_vpop() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 4, "mov", "movzx eax, byte [rdi + 8]"))]
    # movzx/movsx reg,[base+disp] loads-and-extends onto the stack (no dedicated
    # extend-and-store handler), then pops into the destination slot.
    expect("movx" not in kinds)
    expect(kinds[:2] == ["vmovx", "vpop"])


def test_movsx_indexed_from_memory_lowers_to_vmovxidx_then_vpop() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 5, "mov", "movsx rax, word [rdi + rcx*2]"))]
    expect("movxidx" not in kinds)
    expect(kinds[:2] == ["vmovxidx", "vpop"])


def test_movx_micro_op_item_sizes_match_the_handler_advances() -> None:
    # ext, src_size, dst_width live in the key (not the stream); the address operands
    # match the load/scaled-index layouts, with an unused placeholder register byte.
    expect(_item_size(("vmovx", "z", 8, 64, 5, -8)) == _EXPECTED_ITEM_SIZE_VMOVX_Z_8_64_5_8_7)
    expect(_item_size(("vmovxidx", "s", 16, 64, 5, 6, 1, -8)) == _EXPECTED_ITEM_SIZE_VMOVXIDX_S_16_64_5_6_1_8_9)
