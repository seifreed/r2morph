"""Micro-op lowering for the engine VM's reg-reg GP arithmetic.

A single handler that computes a whole native op (``add`` == the MBA fold in one
place) is a fingerprint: identify the handler and you have identified the native
instruction. This module breaks that by lowering each reg-reg op in
{add,sub,xor,and,or} into a sequence of tiny primitives over a virtual operand
stack - ``vpush`` the two source cells, ``v<op>`` fold the top two, ``vpop`` the
result - so the handler set becomes reused primitives shared across every native
op and the bytecode carries the operation as data-flow through the stack rather
than one op-per-handler.

The stack lives in the interpreter's private frame (pointer at ``_VSP_OFFSET``,
cells from ``_VSTACK_BASE``); depth never exceeds two per native op (push, push,
fold, pop nets the pointer back to where it started). The fold reuses the shared
MBA builder, so ``v<op>`` still never spells the native operation.
"""

from __future__ import annotations

from collections.abc import Callable

from r2morph.mutations.code_virtualization_engine_common import (
    _DWORD_BROADCAST,
    _MICROOP_BINOP_KINDS,
    _MICROOP_IMM_KINDS,
    _MICROOP_STACK_KINDS,
    _QWORD_BROADCAST,
    _VSP_OFFSET,
    _VSTACK_BASE,
    VMScheme,
    pack_immediate,
)
from r2morph.mutations.code_virtualization_engine_models import VirtualizedOp
from r2morph.mutations.code_virtualization_mba import _op_mba_compute

# Native reg-reg mnemonic -> its vstack fold primitive, and the inverse.
_BINOP_OF: dict[str, str] = {"add": "vadd", "sub": "vsub", "xor": "vxor", "and": "vand", "or": "vor"}
_MNEMONIC_OF: dict[str, str] = {binop: mnemonic for mnemonic, binop in _BINOP_OF.items()}
# The native reg-reg mnemonics that lower to micro-ops (the encoder's trigger set).
MICROOP_ARITH_MNEMONICS: frozenset[str] = frozenset(_BINOP_OF)
MICROOP_STACK_KINDS: tuple[str, ...] = _MICROOP_STACK_KINDS
MICROOP_BINOP_KINDS: tuple[str, ...] = _MICROOP_BINOP_KINDS
MICROOP_IMM_KINDS: tuple[str, ...] = _MICROOP_IMM_KINDS

_VSP = hex(_VSP_OFFSET)
_VBASE = hex(_VSTACK_BASE)


def microop_handler_body(kind: str, width: int, key: int) -> str:
    """Assembly body for one micro-op primitive; ends with the shared dispatch jump.

    ``vpush s``/``vpop s`` carry one slot-index operand at ``[rsi+1]`` (the only
    field, so no permutation applies); ``v<op>`` carries no operand. The stack
    pointer word and cells are addressed off ``rsp``; only scratch registers
    (rax/r8/r9/r10/rcx) are touched, all dead across the threaded dispatch.
    """
    if kind == "vpush":
        # Read src slot -> r8, push its value onto the vstack, bump the pointer.
        return (
            f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
            "  mov rax, qword ptr [rsp + r8*8]\n"
            f"  mov r9, qword ptr [rsp + {_VSP}]\n"
            f"  mov qword ptr [rsp + r9 + {_VBASE}], rax\n"
            "  add r9, 8\n"
            f"  mov qword ptr [rsp + {_VSP}], r9\n"
            "  add rsi, 2\n  jmp vm_dispatch\n"
        )
    if kind == "vpop":
        # Pop the top cell into the dst slot, drop the pointer.
        return (
            f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
            f"  mov r9, qword ptr [rsp + {_VSP}]\n"
            "  sub r9, 8\n"
            f"  mov rax, qword ptr [rsp + r9 + {_VBASE}]\n"
            "  mov qword ptr [rsp + r8*8], rax\n"
            f"  mov qword ptr [rsp + {_VSP}], r9\n"
            "  add rsi, 2\n  jmp vm_dispatch\n"
        )
    if kind == "vpushi":
        # Push a width-sized immediate. The decode mirrors the single-handler
        # immediate path exactly (width-sized load, un-masked by the key broadcast
        # and r13b broadcast) so value and masking are identical. A 32-bit immediate
        # zero-extends into the low half of the 64-bit cell, which is all the width-32
        # fold reads. The operand is the only field, so it sits at [rsi+1].
        if width == 64:
            key_qword = hex((key * _QWORD_BROADCAST) & 0xFFFFFFFFFFFFFFFF)
            decode = (
                f"  mov rax, qword ptr [rsi+1]\n  mov r10, {key_qword}\n  xor rax, r10\n"
                f"  movzx r10, r13b\n  mov r11, {hex(_QWORD_BROADCAST)}\n  imul r10, r11\n  xor rax, r10\n"
            )
            advance = 9
        else:
            key_dword = hex((key * _DWORD_BROADCAST) & 0xFFFFFFFF)
            decode = (
                f"  mov eax, dword ptr [rsi+1]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
                f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
            )
            advance = 5
        return (
            decode
            + f"  mov r9, qword ptr [rsp + {_VSP}]\n"
            + f"  mov qword ptr [rsp + r9 + {_VBASE}], rax\n"
            + "  add r9, 8\n"
            + f"  mov qword ptr [rsp + {_VSP}], r9\n"
            + f"  add rsi, {advance}\n  jmp vm_dispatch\n"
        )
    # v<op>: pop b (top) into rax and a (below) into r10, fold r10 = a <op> b with no
    # literal native op, push the result back. The operands were pushed dst-then-src,
    # so a == dst and b == src; sub negates b first so a + (-b) == dst - src.
    mnemonic = _MNEMONIC_OF[kind]
    body = (
        f"  mov r9, qword ptr [rsp + {_VSP}]\n"
        "  sub r9, 8\n"
        f"  mov rax, qword ptr [rsp + r9 + {_VBASE}]\n"
        "  sub r9, 8\n"
        f"  mov r10, qword ptr [rsp + r9 + {_VBASE}]\n"
    )
    if mnemonic == "sub":
        body += "  neg rax\n"
    body += _op_mba_compute(mnemonic, key)
    if width == 32:
        body += "  mov r10d, r10d\n"
    body += (
        f"  mov qword ptr [rsp + r9 + {_VBASE}], r10\n"
        "  add r9, 8\n"
        f"  mov qword ptr [rsp + {_VSP}], r9\n"
        "  add rsi, 1\n  jmp vm_dispatch\n"
    )
    return body


def emit_arith_microops(
    op: VirtualizedOp,
    scheme: VMScheme,
    slot_of: tuple[int, ...],
    emit_opcode: Callable[[int], int],
    emit_fields: Callable[[int, list[tuple[str, int]], dict[str, bytes]], None],
    pick: Callable[[tuple[int, ...]], int],
) -> None:
    """Emit the push/push/binop/pop bytecode for one reg-reg arithmetic op.

    Pushes dst then src (so the fold sees a == dst, b == src), folds, pops into dst.
    ``emit_opcode``/``emit_fields``/``pick`` are the encoder's per-build closures.
    """
    dst = {"slot": bytes([slot_of[op.dst_index]])}
    src = {"slot": bytes([slot_of[op.value]])}
    order = [("slot", 1)]
    position = emit_opcode(pick(scheme.dup[("vpush", False, 64)]))
    emit_fields(position, order, dst)
    position = emit_opcode(pick(scheme.dup[("vpush", False, 64)]))
    emit_fields(position, order, src)
    emit_opcode(pick(scheme.dup[(_BINOP_OF[op.mnemonic], False, op.width)]))
    position = emit_opcode(pick(scheme.dup[("vpop", False, 64)]))
    emit_fields(position, order, dst)


def emit_arith_imm_microops(
    op: VirtualizedOp,
    scheme: VMScheme,
    slot_of: tuple[int, ...],
    emit_opcode: Callable[[int], int],
    emit_fields: Callable[[int, list[tuple[str, int]], dict[str, bytes]], None],
    pick: Callable[[tuple[int, ...]], int],
) -> None:
    """Emit push_slot(dst)/push_imm/binop/pop(dst) for one immediate arithmetic op.

    Same dst-then-operand order as the reg-reg form, so ``sub`` folds dst - imm; the
    fold and pop primitives are shared with the reg-reg lowering.
    """
    dst = {"slot": bytes([slot_of[op.dst_index]])}
    position = emit_opcode(pick(scheme.dup[("vpush", False, 64)]))
    emit_fields(position, [("slot", 1)], dst)
    position = emit_opcode(pick(scheme.dup[("vpushi", False, op.width)]))
    emit_fields(position, [("imm", op.width // 8)], {"imm": pack_immediate(op.value, op.width)})
    emit_opcode(pick(scheme.dup[(_BINOP_OF[op.mnemonic], False, op.width)]))
    position = emit_opcode(pick(scheme.dup[("vpop", False, 64)]))
    emit_fields(position, [("slot", 1)], dst)
