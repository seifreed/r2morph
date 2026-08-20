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
from dataclasses import dataclass

from r2morph.core.constants import ARCH_BITS_32, ARCH_BITS_64
from r2morph.mutations.code_virtualization_engine_common import (
    _DWORD_BROADCAST,
    _MICROOP_BINOP_KINDS,
    _MICROOP_IMM_KINDS,
    _MICROOP_STACK_KINDS,
    _QWORD_BROADCAST,
    VMScheme,
    pack_immediate,
)
from r2morph.mutations.code_virtualization_engine_models import VirtualizedOp
from r2morph.mutations.code_virtualization_fold import arith_fold

# Native reg-reg mnemonic -> its vstack fold primitive, and the inverse.
_BINOP_OF: dict[str, str] = {"add": "vadd", "sub": "vsub", "xor": "vxor", "and": "vand", "or": "vor"}
_MNEMONIC_OF: dict[str, str] = {binop: mnemonic for mnemonic, binop in _BINOP_OF.items()}
_SPLIT_IMMEDIATE_MNEMONICS = frozenset({"add", "and", "or", "sub", "xor"})
# The native reg-reg mnemonics that lower to micro-ops (the encoder's trigger set).
MICROOP_ARITH_MNEMONICS: frozenset[str] = frozenset(_BINOP_OF)
MICROOP_STACK_KINDS: tuple[str, ...] = _MICROOP_STACK_KINDS
MICROOP_BINOP_KINDS: tuple[str, ...] = _MICROOP_BINOP_KINDS
MICROOP_IMM_KINDS: tuple[str, ...] = _MICROOP_IMM_KINDS


@dataclass(frozen=True)
class MicroopHandlerConfig:
    key: str
    key_dword: str
    key_qword: str
    vsp_offset: int
    vstack_base: int
    arith_variant: int = 0
    record_padding: int = 0
    advance_variant: int = 0


def _advance_asm(amount: int, variant: int) -> str:
    """Advance the virtual program counter through equivalent instruction forms."""
    if variant:
        return f"  lea rsi, [rsi + {amount}]\n"
    return f"  add rsi, {amount}\n"


@dataclass(frozen=True)
class MicroopEmitter:
    scheme: VMScheme
    slot_of: tuple[int, ...]
    emit_opcode: Callable[[int], int]
    emit_fields: Callable[[int, list[tuple[str, int]], dict[str, bytes]], None]
    pick: Callable[[tuple[int, ...]], int]


def microop_handler_body(kind: str, width: int, config: MicroopHandlerConfig) -> str:
    """Assembly body for one micro-op primitive; ends with the shared dispatch jump.

    ``vpush s``/``vpop s`` carry one slot-index operand at ``[rsi+1]`` (the only
    field, so no permutation applies); ``v<op>`` carries no operand. The stack
    pointer word (``vsp_offset``) and cells (``vstack_base``) are addressed off
    ``rsp`` at this build's frame offsets; only scratch registers (rax/r8/r9/r10/
    rcx) are touched, all dead across the threaded dispatch.
    """
    vsp_hex = hex(config.vsp_offset)
    vstack_base_hex = hex(config.vstack_base)
    if kind == "vpush":
        # Read src slot -> r8, push its value onto the vstack, bump the pointer.
        return (
            f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {config.key}\n  xor r8b, r13b\n"
            "  mov rax, qword ptr [rsp + r8*8]\n"
            f"  mov r9, qword ptr [rsp + {vsp_hex}]\n"
            f"  mov qword ptr [rsp + r9 + {vstack_base_hex}], rax\n"
            "  add r9, 8\n"
            f"  mov qword ptr [rsp + {vsp_hex}], r9\n"
            + _advance_asm(2 + config.record_padding, config.advance_variant)
            + "  jmp vm_dispatch\n"
        )
    if kind == "vpop":
        # Pop the top cell into the dst slot, drop the pointer.
        return (
            f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {config.key}\n  xor r8b, r13b\n"
            f"  mov r9, qword ptr [rsp + {vsp_hex}]\n"
            "  sub r9, 8\n"
            f"  mov rax, qword ptr [rsp + r9 + {vstack_base_hex}]\n"
            "  mov qword ptr [rsp + r8*8], rax\n"
            f"  mov qword ptr [rsp + {vsp_hex}], r9\n"
            + _advance_asm(2 + config.record_padding, config.advance_variant)
            + "  jmp vm_dispatch\n"
        )
    if kind == "vpushi":
        # Push a width-sized immediate. The decode mirrors the single-handler
        # immediate path exactly (width-sized load, un-masked by the key broadcast
        # and r13b broadcast) so value and masking are identical. A 32-bit immediate
        # zero-extends into the low half of the 64-bit cell, which is all the width-32
        # fold reads. The operand is the only field, so it sits at [rsi+1].
        if width == ARCH_BITS_64:
            decode = (
                f"  mov rax, qword ptr [rsi+1]\n  mov r10, {config.key_qword}\n  xor rax, r10\n"
                f"  movzx r10, r13b\n  mov r11, {hex(_QWORD_BROADCAST)}\n  imul r10, r11\n  xor rax, r10\n"
            )
            advance = 9
        else:
            decode = (
                f"  mov eax, dword ptr [rsi+1]\n  mov r11d, {config.key_dword}\n  xor eax, r11d\n"
                f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
            )
            advance = 5
        return (
            decode
            + f"  mov r9, qword ptr [rsp + {vsp_hex}]\n"
            + f"  mov qword ptr [rsp + r9 + {vstack_base_hex}], rax\n"
            + "  add r9, 8\n"
            + f"  mov qword ptr [rsp + {vsp_hex}], r9\n"
            + _advance_asm(advance + config.record_padding, config.advance_variant)
            + "  jmp vm_dispatch\n"
        )
    # v<op>: pop b (top) into rax and a (below) into r10, fold r10 = a <op> b with no
    # literal native op, push the result back. The operands were pushed dst-then-src,
    # so a == dst and b == src; sub negates b first so a + (-b) == dst - src.
    mnemonic = _MNEMONIC_OF[kind]
    body = (
        f"  mov r9, qword ptr [rsp + {vsp_hex}]\n"
        "  sub r9, 8\n"
        f"  mov rax, qword ptr [rsp + r9 + {vstack_base_hex}]\n"
        "  sub r9, 8\n"
        f"  mov r10, qword ptr [rsp + r9 + {vstack_base_hex}]\n"
    )
    if mnemonic == "sub":
        body += "  neg rax\n"
    body += arith_fold(mnemonic, 0, config.arith_variant)
    if width == ARCH_BITS_32:
        body += "  mov r10d, r10d\n"
    body += (
        f"  mov qword ptr [rsp + r9 + {vstack_base_hex}], r10\n"
        "  add r9, 8\n"
        f"  mov qword ptr [rsp + {vsp_hex}], r9\n"
        + _advance_asm(1 + config.record_padding, config.advance_variant)
        + "  jmp vm_dispatch\n"
    )
    return body


def emit_arith_microops(op: VirtualizedOp, emitter: MicroopEmitter) -> None:
    """Emit the push/push/binop/pop bytecode for one reg-reg arithmetic op.

    Pushes dst then src (so the fold sees a == dst, b == src), folds, pops into dst.
    ``emit_opcode``/``emit_fields``/``pick`` are the encoder's per-build closures.
    """
    dst = {"slot": bytes([emitter.slot_of[op.dst_index]])}
    src = {"slot": bytes([emitter.slot_of[op.value]])}
    order = [("slot", 1)]
    position = emitter.emit_opcode(emitter.pick(emitter.scheme.dup[("vpush", False, 64)]))
    emitter.emit_fields(position, order, dst)
    position = emitter.emit_opcode(emitter.pick(emitter.scheme.dup[("vpush", False, 64)]))
    emitter.emit_fields(position, order, src)
    emitter.emit_opcode(emitter.pick(emitter.scheme.dup[(_BINOP_OF[op.mnemonic], False, op.width)]))
    position = emitter.emit_opcode(emitter.pick(emitter.scheme.dup[("vpop", False, 64)]))
    emitter.emit_fields(position, order, dst)


def emit_arith_imm_microops(op: VirtualizedOp, emitter: MicroopEmitter) -> None:
    """Emit push_slot(dst)/push_imm/binop/pop(dst) for one immediate arithmetic op.

    Same dst-then-operand order as the reg-reg form, so ``sub`` folds dst - imm; the
    fold and pop primitives are shared with the reg-reg lowering.
    """
    dst = {"slot": bytes([emitter.slot_of[op.dst_index]])}
    position = emitter.emit_opcode(emitter.pick(emitter.scheme.dup[("vpush", False, 64)]))
    emitter.emit_fields(position, [("slot", 1)], dst)
    immediate_values: tuple[int, ...] = (op.value,)
    if emitter.scheme.immediate_split and op.mnemonic in _SPLIT_IMMEDIATE_MNEMONICS:
        if op.mnemonic == "xor":
            first = (1 << (op.width - 1)) - 1
            immediate_values = (first, op.value ^ first)
        elif op.mnemonic == "and":
            immediate_values = ((1 << op.width) - 1, op.value)
        elif op.mnemonic == "or":
            immediate_values = (0, op.value)
        else:
            first = op.value // 2
            immediate_values = (first, op.value - first)
    for immediate in immediate_values:
        position = emitter.emit_opcode(emitter.pick(emitter.scheme.dup[("vpushi", False, op.width)]))
        emitter.emit_fields(position, [("imm", op.width // 8)], {"imm": pack_immediate(immediate, op.width)})
        emitter.emit_opcode(emitter.pick(emitter.scheme.dup[(_BINOP_OF[op.mnemonic], False, op.width)]))
    position = emitter.emit_opcode(emitter.pick(emitter.scheme.dup[("vpop", False, 64)]))
    emitter.emit_fields(position, [("slot", 1)], dst)
