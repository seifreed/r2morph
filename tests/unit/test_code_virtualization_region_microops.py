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
    # The 1:1 arithmetic handler is gone; each op became push/push/binop/pop.
    assert "opmba" not in kinds and "op_add" not in kinds
    assert kinds.count("vbinop") == 2 and kinds.count("vpush") == 4 and kinds.count("vpop") == 2
    # add and xor share the SAME vpush/vpop primitives; only the fold differs.
    binops = {item[1] for item in items if item[0] == "vbinop"}
    assert binops == {"add", "xor"}


def test_flag_dead_immediate_arith_lowers_with_vpushi() -> None:
    items = _flag_dead_arith_region(_insn(0x1003, 3, "add", "add eax, 5"))
    kinds = [item[0] for item in items]
    # The immediate form pushes the constant via vpushi, sharing vpush/vpop/vbinop.
    assert "vpushi" in kinds
    assert kinds.count("vbinop") == 2 and kinds.count("vpop") == 2


def test_flag_live_arith_is_not_lowered() -> None:
    # `add` whose flags a following `jns` reads stays a single flag-synthesizing
    # handler (opsynth) - only the flag-dead subset lowers to micro-ops this slice.
    insns = [
        _insn(0x1000, 3, "add", "add eax, ebx"),
        _insn(0x1003, 2, "cjmp", "jns 0x1000", jump=0x1000, fail=0x1005),
        _insn(0x1005, 1, "ret", "ret"),
    ]
    region = extract_region(insns)
    assert region is not None
    kinds = [item[0] for item in region.instructions]
    assert "opsynth" in kinds
    assert "vbinop" not in kinds


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
    assert _item_size(("vpush", 3)) == 2
    assert _item_size(("vpop", 3)) == 2
    assert _item_size(("vpushi", 5, 32)) == 5
    assert _item_size(("vpushi", 5, 64)) == 9
    assert _item_size(("vbinop", "add", 64)) == 1
