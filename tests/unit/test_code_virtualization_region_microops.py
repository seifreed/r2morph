"""Region VM micro-op lowering: flag-dead arithmetic becomes virtual-stack primitives.

These pin the structural contract that a flag-dead reg-reg/immediate arithmetic op no
longer maps 1:1 to a native handler but lowers to a push/push/fold/pop micro-op
sequence over the interpreter's private operand stack, with the stack primitives
shared across distinct native ops. Semantic parity through the lowered path is covered
by the Unicorn exit-code fixtures in the integration suite (the flag-dead add/sub/bool
fixtures now route through these micro-ops).
"""

from __future__ import annotations

import random
import struct

from r2morph.mutations.code_virtualization_region import extract_region
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_handlers import _VSP_OFFSET
from r2morph.mutations.code_virtualization_region_nesting import build_nested_region_blob


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
    assert region is not None
    return list(region.instructions)


def test_flag_dead_reg_reg_arith_lowers_to_shared_microop_sequence() -> None:
    items = _flag_dead_arith_region(_insn(0x1003, 3, "xor", "xor eax, ecx"))
    kinds = [item[0] for item in items]
    # The 1:1 arithmetic handler is gone; each op became push/push/binop/pop (the
    # trailing cmp also lowers now, so only the per-op fold/pop counts are asserted).
    assert "opmba" not in kinds and "op_add" not in kinds
    assert kinds.count("vbinop") == 2 and kinds.count("vpop") == 2
    # add and xor share the SAME vpush/vpop primitives; only the fold differs.
    binops = {item[1] for item in items if item[0] == "vbinop"}
    assert binops == {"add", "xor"}


def test_flag_dead_immediate_arith_lowers_with_vpushi() -> None:
    items = _flag_dead_arith_region(_insn(0x1003, 3, "add", "add eax, 5"))
    kinds = [item[0] for item in items]
    # The immediate form pushes the constant via vpushi, sharing vpush/vpop/vbinop.
    assert "vpushi" in kinds
    assert kinds.count("vbinop") == 2 and kinds.count("vpop") == 2


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
    assert region is not None
    kinds = [item[0] for item in region.instructions]
    assert "opsynth" not in kinds
    assert kinds.count("vbinopsynth") == 1
    assert kinds.count("vpush") == 2 and kinds.count("vpop") == 1


def test_shift_lowers_to_shared_push_shift_pop_sequence() -> None:
    # A native shl/shr/sar reg,imm lowers to vpush(slot)/vshift/vpop(slot), reusing the
    # same stack primitives as the arithmetic folds instead of a dedicated shift handler.
    insns = [
        _insn(0x1000, 3, "shl", "shl eax, 4"),
        _insn(0x1003, 2, "cjmp", "jne 0x1000", jump=0x1000, fail=0x1005),
        _insn(0x1005, 1, "ret", "ret"),
    ]
    region = extract_region(insns)
    assert region is not None
    kinds = [item[0] for item in region.instructions]
    # No standalone shift handler survives; the shift is a shared push/shift/pop.
    assert "shift" not in kinds and "shl" not in {k.split("_")[0] for k in region.op_keys}
    assert kinds.count("vshift") == 1
    assert kinds.count("vpush") == 1 and kinds.count("vpop") == 1


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
    region = extract_region(insns, random.Random(1))
    assert region is not None
    blob = build_nested_region_blob(region, 0x401000, random.Random(7), depth=2)
    assert blob is not None
    # mov qword ptr [rsp + _VSP_OFFSET], 0  (REX.W C7 /0, SIB base=rsp, disp32, imm32=0)
    vsp_zero = b"\x48\xc7\x84\x24" + struct.pack("<i", _VSP_OFFSET) + b"\x00\x00\x00\x00"
    assert vsp_zero in blob


def test_micro_op_item_sizes_match_the_handler_advances() -> None:
    # The encoded byte length of each micro-op item must equal its handler's rsi
    # advance, or the virtual instruction pointer desyncs. vpush/vpop carry one slot
    # byte; vpushi carries only its width-sized immediate; vbinop carries nothing.
    assert _item_size(("vshift", "shl", 3, 64)) == 2
    assert _item_size(("vpush", 3)) == 2
    assert _item_size(("vpop", 3)) == 2
    assert _item_size(("vpushi", 5, 32)) == 5
    assert _item_size(("vpushi", 5, 64)) == 9
    assert _item_size(("vbinop", "add", 64)) == 1
    assert _item_size(("vbinopsynth", "add", 64)) == 1
    assert _item_size(("vload", 5, -8, 64)) == 7
    assert _item_size(("vstore", 5, -8, 64)) == 7
    assert _item_size(("vloadidx", 5, 6, 3, -8, 64)) == 9
    assert _item_size(("vcmpsynth", "cmp", 64)) == 1
    assert _item_size(("vcmpsynth", "test", 32)) == 1


def _memory_region(access: dict[str, object]) -> list[tuple[object, ...]]:
    """Region items for a single base+disp memory instruction then a terminator."""
    region = extract_region([access, _insn(0x1010, 1, "ret", "ret")])
    assert region is not None
    return list(region.instructions)


def test_base_disp_load_lowers_to_vload_then_vpop() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 5, "mov", "mov rax, qword [rsp - 8]"))]
    # mov reg,[base+disp] loads onto the stack, then pops into the destination slot.
    assert "load" not in kinds
    assert kinds[:2] == ["vload", "vpop"]


def test_base_disp_store_lowers_to_vpush_then_vstore() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 5, "mov", "mov qword [rsp - 0x10], rax"))]
    # mov [base+disp],reg pushes the register then stores the stack top.
    assert "store" not in kinds
    assert kinds[:2] == ["vpush", "vstore"]


def test_mem_source_arith_lowers_to_vpush_vload_vbinopsynth_vpop() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 3, "add", "add rax, qword [rsp - 8]"))]
    # <op> reg,[base+disp] pushes reg, loads the memory operand, folds them with the
    # flag-synthesizing stack fold (mem arith is always flag-live today), pops to reg.
    assert "opmem" not in kinds
    assert kinds[:4] == ["vpush", "vload", "vbinopsynth", "vpop"]


def test_indexed_mem_source_arith_lowers_to_vpush_vloadidx_vbinopsynth_vpop() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 4, "add", "add rax, qword [rax + rcx*8]"))]
    # <op> reg,[base+index*scale+disp] pushes reg, loads the indexed memory operand
    # via the scaled-index prologue, folds with flag synthesis, pops back to reg.
    assert "opmemidx" not in kinds
    assert kinds[:4] == ["vpush", "vloadidx", "vbinopsynth", "vpop"]


def test_read_modify_write_lowers_to_vload_vpush_vbinopsynth_vstore() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 4, "add", "add qword [rax - 8], rcx"))]
    # <op> [base+disp],reg loads the memory value, pushes the register, folds them,
    # and stores the result back to the same address (recomputed, base+disp is fixed).
    assert "opmemdst" not in kinds
    assert kinds[:4] == ["vload", "vpush", "vbinopsynth", "vstore"]


def _compare_region(compare: dict[str, object]) -> list[str]:
    """Region item kinds for a compare that drives a conditional branch."""
    insns = [
        compare,
        _insn(0x1010, 2, "cjmp", "jne 0x1000", jump=0x1000, fail=0x1012),
        _insn(0x1012, 1, "ret", "ret"),
    ]
    region = extract_region(insns)
    assert region is not None
    return [item[0] for item in region.instructions]


def test_cmp_reg_reg_lowers_to_vpush_vpush_vcmpsynth() -> None:
    kinds = _compare_region(_insn(0x1000, 3, "cmp", "cmp rax, rbx"))
    # The single cmp handler is gone; both operands are pushed and the flags are
    # synthesized off the stack with no stored result.
    assert "cmp" not in kinds
    assert kinds[:3] == ["vpush", "vpush", "vcmpsynth"]


def test_cmp_reg_imm_lowers_with_vpushi() -> None:
    kinds = _compare_region(_insn(0x1000, 4, "cmp", "cmp rax, 5"))
    assert "cmp" not in kinds
    assert kinds[:3] == ["vpush", "vpushi", "vcmpsynth"]


def test_test_reg_reg_lowers_to_vcmpsynth() -> None:
    kinds = _compare_region(_insn(0x1000, 3, "acmp", "test rax, rbx"))
    assert "test" not in kinds
    assert kinds[:3] == ["vpush", "vpush", "vcmpsynth"]


def test_cmp_with_memory_operand_lowers_to_vpush_vload_vcmpsynth() -> None:
    kinds = _compare_region(_insn(0x1000, 4, "cmp", "cmp rax, qword [rsp - 8]"))
    # cmp reg,[base+disp] reuses the base+disp vload primitive before the compare.
    assert "cmpmem" not in kinds
    assert kinds[:3] == ["vpush", "vload", "vcmpsynth"]


def test_cmp_with_rip_relative_operand_lowers_to_vpush_vloadrip_vcmpsynth() -> None:
    kinds = _compare_region(_insn(0x1000, 7, "cmp", "cmp rax, qword [rip + 0x2000]"))
    # cmp reg,[rip+disp] reuses the rip-relative vloadrip primitive before the compare.
    assert "cmpriprel" not in kinds
    assert kinds[:3] == ["vpush", "vloadrip", "vcmpsynth"]


def test_rip_relative_load_lowers_to_vloadrip() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 7, "mov", "mov rax, qword [rip + 0x2000]"))]
    # mov reg,[rip+disp] pushes the global via vloadrip then pops it into the register.
    assert "riprel_load" not in kinds
    assert kinds[:2] == ["vloadrip", "vpop"]


def test_rip_relative_store_lowers_to_vpush_vstorerip() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 7, "mov", "mov qword [rip + 0x2000], rax"))]
    assert "riprel_store" not in kinds
    assert kinds[:2] == ["vpush", "vstorerip"]


def test_rip_relative_arith_lowers_with_vloadrip_and_vbinopsynth() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 7, "add", "add rax, qword [rip + 0x2000]"))]
    # <op> reg,[rip+disp] pushes reg, loads the global, folds them with the
    # flag-synthesizing stack fold, pops to reg.
    assert "opriprel" not in kinds
    assert kinds[:4] == ["vpush", "vloadrip", "vbinopsynth", "vpop"]


def test_rip_relative_rmw_lowers_to_vloadrip_vbinopsynth_vstorerip() -> None:
    kinds = [item[0] for item in _memory_region(_insn(0x1000, 7, "add", "add qword [rip + 0x2000], rax"))]
    # <op> [rip+disp],reg loads the global, pushes reg, folds, stores the result back.
    assert "opmemdstrip" not in kinds
    assert kinds[:4] == ["vloadrip", "vpush", "vbinopsynth", "vstorerip"]


def test_rip_relative_micro_op_item_sizes() -> None:
    # opcode + (unused) reg slot + 4-byte bytecode-relative offset.
    assert _item_size(("vloadrip", 0, 64)) == 6
    assert _item_size(("vstorerip", 0, 64)) == 6
