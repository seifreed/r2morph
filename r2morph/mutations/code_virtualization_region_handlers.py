"""
Assembly bodies for the region VM's opcode handlers.

Each function here renders the native assembly for one VM handler instance:
it decrypts the operands embedded in the bytecode stream, applies the real
operation, captures the resulting RFLAGS where the operation defines them,
advances the bytecode pointer, and jumps back to the dispatch loop. The
handlers are pure string builders keyed by a ``handler_key`` and the
per-instance XOR key; :mod:`code_virtualization_region` owns the dispatch
table and stitches these instances together.
"""

from __future__ import annotations

from dataclasses import dataclass

from r2morph.mutations.code_virtualization_fold import arith_fold
from r2morph.mutations.code_virtualization_layout import (
    field_offsets,
    imul3_offsets,
    op_offsets,
    shift_offsets,
)
from r2morph.mutations.code_virtualization_region_compare import compare_compute
from r2morph.mutations.code_virtualization_region_flags import synth_flags_asm as _synth_flags_asm
from r2morph.mutations.code_virtualization_region_models import _DWORD_BROADCAST, _QWORD_BROADCAST
from r2morph.mutations.code_virtualization_region_shift import shift_flag_capture_asm

_BYTE_WIDTH_BITS = 8
_WORD_WIDTH_BITS = 16
_DWORD_WIDTH_BITS = 32
_QWORD_WIDTH_BITS = 64


@dataclass(frozen=True)
class IntegerHandlerConfig:
    handler_key: str
    key: str
    key_qword: str
    key_dword: str
    field_perm: int = 0
    flag_variant: int = 0
    arith_variant: int = 0
    compare_variant: int = 0


# Stack frame: 16 GP context slots in [0x00, 0x80), the captured RFLAGS and the
# self-checksum byte in [0x80, 0x100) (both slots relocated per build), the 16 XMM
# save slots (16 bytes each) in [0x100, 0x200), the System V red zone in [0x200,
# 0x280), and the interpreter's virtual operand stack in [0x280, 0x300). Nothing
# reads the red zone by offset, so riding it below the new vstack window only
# enlarges the reservation; every GP-slot offset (rsp + slot*8) is unchanged, so
# the handler addressing is untouched.
_FRAME_SIZE = 0x300
_FLAGS_OFFSET = 0x80
# Base of the 16 XMM save slots (16 bytes each); slot i lives at
# [rsp + _XMM_SAVE_OFFSET + i*16). Spilled/reloaded only when a region carries FP.
_XMM_SAVE_OFFSET = 0x100
# Runtime operand-cipher key: the self-checksum broadcast to 32/64 bits, computed
# once at entry into these free slots (the [0x200, 0x280) window between the XMM
# save area and the virtual stack). Every handler decrypts its multi-byte operands
# against these rather than a build-constant key, so no operand-cipher literal is
# exposed; the byte-wide key is the checksum slot itself, read directly.
_KEY_DWORD_SLOT = 0x200
_KEY_QWORD_SLOT = 0x208
# The interpreter's private virtual operand stack: a pointer word (current depth in
# bytes, starts 0) at _VSP_OFFSET and 8 cells from _VSTACK_BASE. Micro-op lowering
# folds arithmetic through this stack (vpush/vbinop/vpop); peak depth is two cells
# per op, so 8 is 4x headroom. Sits above the red zone, disjoint from the GP slots,
# the relocated flags/checksum slots, the XMM area, and the nested dispatcher slots.
_VSP_OFFSET = 0x280
_VSTACK_BASE = 0x288
# The program's virtual stack is relocated this far below the VM frame so the
# function's own push/pop traffic never collides with the spilled context. Must
# be 16-aligned and strictly greater than _FRAME_SIZE so the relocated stack
# stays below the frame.
_GUARD = 0x380


def _unmask_dword(scratch: str) -> str:
    """Un-mask a dword immediate/displacement (in eax) with the item's stream
    position: r13b holds it from the dispatch, broadcast to 32 bits. ``scratch``
    is a register free at the call site (typically the just-used key temp)."""
    return (
        f"  movzx {scratch}d, r13b\n"
        f"  imul {scratch}d, {scratch}d, {hex(_DWORD_BROADCAST)}\n"
        f"  xor eax, {scratch}d\n"
    )


def _unmask_qword(scratch: str, scratch2: str) -> str:
    """Un-mask a qword immediate (in rax) with the item's stream position (r13b),
    broadcast to 64 bits. Both scratch registers must be free at the call site."""
    return (
        f"  movzx {scratch}, r13b\n  mov {scratch2}, {hex(_QWORD_BROADCAST)}\n"
        f"  imul {scratch}, {scratch2}\n  xor rax, {scratch}\n"
    )


def _op_handler_asm(handler_key: str, key: str, key_qword: str, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for an arithmetic/mov handler (decrypts, applies, captures flags)."""
    _, mnemonic, mode, width_text = handler_key.split("_")
    width = int(width_text)
    is_immediate = mode == "i"
    off = field_offsets(handler_key, field_perm)
    body = f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
    if is_immediate and width == _QWORD_WIDTH_BITS:
        body += f"  mov rax, qword ptr [rsi+{off['imm']}]\n  mov r10, {key_qword}\n  xor rax, r10\n" + _unmask_qword(
            "r10", "r11"
        )
        advance = 10
    elif is_immediate:
        body += f"  mov eax, dword ptr [rsi+{off['imm']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n" + _unmask_dword(
            "r11"
        )
        advance = 6
    else:
        body += f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        body += (
            "  mov rax, qword ptr [rsp+r9*8]\n" if width == _QWORD_WIDTH_BITS else "  mov eax, dword ptr [rsp+r9*8]\n"
        )
        advance = 3
    # Read-modify-write through r11 with the slot store AFTER the flag capture, so the
    # register-file cipher's encrypting xor on the store never clobbers the op's flags.
    if mnemonic == "mov":
        body += "  mov qword ptr [rsp+r8*8], rax\n"
    elif width == _QWORD_WIDTH_BITS:
        body += (
            f"  mov r11, qword ptr [rsp+r8*8]\n  {mnemonic} r11, rax\n"
            f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
            "  mov qword ptr [rsp+r8*8], r11\n"
        )
    else:
        body += (
            f"  mov r11d, dword ptr [rsp+r8*8]\n  {mnemonic} r11d, eax\n"
            f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
            "  mov qword ptr [rsp+r8*8], r11\n"
        )
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _op_mba_handler_asm(config: IntegerHandlerConfig) -> str:
    """Assembly body for a flag-dead ``add``/``sub`` handler.

    The region's flag-liveness analysis proved this op's flags are never read, so
    the result is computed with a mixed boolean-arithmetic rewrite (no literal
    add/sub) and no flags are captured. ``sub a, b`` is folded as ``add a, -b``.
    The destination is loaded into r10, the source/immediate into rax, and the
    MBA fold leaves the result in r10. A 32-bit destination zero-extends.
    """
    handler_key, key, key_qword, key_dword = config.handler_key, config.key, config.key_qword, config.key_dword
    field_perm, arith_variant = config.field_perm, config.arith_variant
    _, mnemonic, mode, width_text = handler_key.split("_")
    width = int(width_text)
    is_immediate = mode == "i"
    off = field_offsets(handler_key, field_perm)
    body = f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
    if is_immediate and width == _QWORD_WIDTH_BITS:
        body += f"  mov rax, qword ptr [rsi+{off['imm']}]\n  mov r10, {key_qword}\n  xor rax, r10\n" + _unmask_qword(
            "r10", "r11"
        )
        advance = 10
    elif is_immediate:
        body += f"  mov eax, dword ptr [rsi+{off['imm']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n" + _unmask_dword(
            "r11"
        )
        advance = 6
    else:
        body += f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        body += (
            "  mov rax, qword ptr [rsp+r9*8]\n" if width == _QWORD_WIDTH_BITS else "  mov eax, dword ptr [rsp+r9*8]\n"
        )
        advance = 3
    # sub a, b == add a, (-b): negate the source, then the same MBA add fold.
    if mnemonic == "sub":
        body += "  neg rax\n"
    body += "  mov r10, qword ptr [rsp+r8*8]\n" if width == _QWORD_WIDTH_BITS else "  mov r10d, dword ptr [rsp+r8*8]\n"
    body += arith_fold(mnemonic, 0, arith_variant)
    if width == _QWORD_WIDTH_BITS:
        body += "  mov qword ptr [rsp+r8*8], r10\n"
    else:
        body += "  mov r10d, r10d\n  mov qword ptr [rsp+r8*8], r10\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _op_synth_handler_asm(config: IntegerHandlerConfig) -> str:
    """Assembly body for a flag-LIVE ``add``/``sub`` handler.

    Where ``_op_mba_handler_asm`` serves the flag-dead case (no flag capture), this
    serves ops whose flags a later branch reads: it computes the result with the
    same MBA fold (no literal add/sub) AND synthesizes the readable flags by hand
    (no ``pushfq`` of a literal op), so the handler contains no flag-setting native
    arithmetic at all. The original operands are saved in rbx/rbp before the MBA
    (which clobbers only r10/rax/rcx) so the synthesis can read a, b and the result.
    """
    handler_key, key, key_qword, key_dword = config.handler_key, config.key, config.key_qword, config.key_dword
    field_perm, flag_variant, arith_variant = config.field_perm, config.flag_variant, config.arith_variant
    _, mnemonic, mode, width_text = handler_key.split("_")
    width = int(width_text)
    is_immediate = mode == "i"
    off = field_offsets(handler_key, field_perm)
    body = f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
    if is_immediate and width == _QWORD_WIDTH_BITS:
        body += f"  mov rax, qword ptr [rsi+{off['imm']}]\n  mov r10, {key_qword}\n  xor rax, r10\n" + _unmask_qword(
            "r10", "r11"
        )
        advance = 10
    elif is_immediate:
        body += f"  mov eax, dword ptr [rsi+{off['imm']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n" + _unmask_dword(
            "r11"
        )
        advance = 6
    else:
        body += f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        body += (
            "  mov rax, qword ptr [rsp+r9*8]\n" if width == _QWORD_WIDTH_BITS else "  mov eax, dword ptr [rsp+r9*8]\n"
        )
        advance = 3
    # Save the original operands (b before any negation, a before the MBA) so the
    # flag synthesis can read them alongside the result.
    body += "  mov rbp, rax\n"
    body += "  mov r10, qword ptr [rsp+r8*8]\n" if width == _QWORD_WIDTH_BITS else "  mov r10d, dword ptr [rsp+r8*8]\n"
    body += "  mov rbx, r10\n"
    if mnemonic == "sub":
        body += "  neg rax\n"
    body += arith_fold(mnemonic, 0, arith_variant)
    if width == _DWORD_WIDTH_BITS:
        body += "  mov r10d, r10d\n"
    # add/sub keep their arithmetic flags; xor/and/or clear CF and OF (logic mode).
    body += _synth_flags_asm(width, mnemonic if mnemonic in ("add", "sub") else "logic", flag_variant)
    body += f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    body += "  mov qword ptr [rsp+r8*8], r10\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _incdec_handler_asm(handler_key: str, key: str, flag_variant: int = 0, arith_variant: int = 0) -> str:
    """Assembly body for ``inc reg`` / ``dec reg``.

    inc/dec leave CF untouched (unlike add/sub by one), so the result is computed
    with the MBA fold (a +/- 1) and OF/SF/ZF/PF are synthesized exactly like add/sub
    with the second operand 1, while CF is carried over unchanged from the captured
    flags slot - no literal inc/dec and no pushfq. A 32-bit form zero-extends.
    """
    _, mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
    body += "  mov r10, qword ptr [rsp+r8*8]\n" if width == _QWORD_WIDTH_BITS else "  mov r10d, dword ptr [rsp+r8*8]\n"
    body += "  mov rbx, r10\n  mov ebp, 1\n"
    if mnemonic == "inc":
        body += "  mov eax, 1\n"
        synth_mode = "add"
    else:
        body += "  mov rax, -1\n"
        synth_mode = "sub"
    body += arith_fold("add", 0, arith_variant)  # r10 = a +/- 1
    if width == _DWORD_WIDTH_BITS:
        body += "  mov r10d, r10d\n"
    elif width == _BYTE_WIDTH_BITS:
        # 8-bit: mask the operand and result to the low byte so the flag synthesis
        # keys the sign/overflow off bit 7, not the slot's upper bytes.
        body += "  and ebx, 0xFF\n  and r10d, 0xFF\n"
    elif width == _WORD_WIDTH_BITS:
        body += "  and ebx, 0xFFFF\n  and r10d, 0xFFFF\n"
    body += _synth_flags_asm(width, synth_mode, flag_variant)
    # inc/dec preserve CF: drop the synthesized carry (bit 0) and OR in the program's.
    body += f"  and r11, -2\n  mov rcx, qword ptr [rsp+{_FLAGS_OFFSET}]\n  and ecx, 1\n  or r11, rcx\n"
    body += f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    if width == _BYTE_WIDTH_BITS:
        # An 8-bit inc/dec writes only the low byte: merge it back over the slot's
        # preserved upper bytes rather than overwriting the whole 64-bit cell.
        body += "  mov rcx, qword ptr [rsp+r8*8]\n  and rcx, -256\n  or r10, rcx\n"
    elif width == _WORD_WIDTH_BITS:
        # A 16-bit inc/dec writes only the low word: merge over the upper 48 bits.
        body += "  mov rcx, qword ptr [rsp+r8*8]\n  and rcx, -65536\n  or r10, rcx\n"
    body += "  mov qword ptr [rsp+r8*8], r10\n"
    return body + "  add rsi, 2\n  jmp vm_dispatch\n"


def _compare_handler_asm(config: IntegerHandlerConfig) -> str:
    """Assembly body for a cmp/test handler (synthesizes flags, stores no result).

    cmp/test exist only to set flags a branch reads, so both compute the comparison
    with the MBA fold (cmp == ``a - b``, test == ``a & b``; no literal cmp/test) and
    synthesize the readable flags by hand (no pushfq of a literal op). The original
    operands are saved in rbx/rbp before the MBA so the synthesis can read a, b and
    the result; nothing is written back to a register slot.
    """
    handler_key, key, key_qword, key_dword = config.handler_key, config.key, config.key_qword, config.key_dword
    field_perm, flag_variant = config.field_perm, config.flag_variant
    arith_variant, compare_variant = config.arith_variant, config.compare_variant
    mnemonic, mode, width_text = handler_key.split("_")
    width = int(width_text)
    is_immediate = mode == "i"
    # cmp/test carry the same operand fields as an arithmetic op (a slot plus an
    # immediate or a second slot), so they share the arith layout.
    off = op_offsets(is_immediate, width, field_perm)
    body = f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
    if is_immediate and width == _QWORD_WIDTH_BITS:
        body += f"  mov rax, qword ptr [rsi+{off['imm']}]\n  mov r10, {key_qword}\n  xor rax, r10\n" + _unmask_qword(
            "r10", "r11"
        )
        advance = 10
    elif is_immediate and width == _BYTE_WIDTH_BITS:
        # The 8-bit immediate is a single byte, position+key masked like a slot byte.
        body += f"  movzx eax, byte ptr [rsi+{off['imm']}]\n  xor al, {key}\n  xor al, r13b\n"
        advance = 3
    elif is_immediate:
        body += f"  mov eax, dword ptr [rsi+{off['imm']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n" + _unmask_dword(
            "r11"
        )
        advance = 6
    else:
        body += f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        body += (
            "  mov rax, qword ptr [rsp+r9*8]\n" if width == _QWORD_WIDTH_BITS else "  mov eax, dword ptr [rsp+r9*8]\n"
        )
        advance = 3
    # Save the original operands (b before any negation, a before the MBA).
    body += "  mov rbp, rax\n"
    body += "  mov r10, qword ptr [rsp+r8*8]\n" if width == _QWORD_WIDTH_BITS else "  mov r10d, dword ptr [rsp+r8*8]\n"
    body += "  mov rbx, r10\n"
    synth_mode = "sub" if mnemonic == "cmp" else "logic"
    if compare_variant == 0:
        if mnemonic == "cmp":
            body += "  neg rax\n" + arith_fold("add", 0, arith_variant)  # r10 = a - b
        else:
            body += arith_fold("and", 0, arith_variant)  # r10 = a & b
    else:
        body += compare_compute(mnemonic, 0, arith_variant, compare_variant)
    if width == _DWORD_WIDTH_BITS:
        body += "  mov r10d, r10d\n"
    elif width == _BYTE_WIDTH_BITS:
        # 8-bit compare: mask the operands and result to the low byte so the flag
        # synthesis (which keys the sign bit off width-1 = 7 and reads a/b for CF/OF)
        # sees clean 8-bit values, not the upper bytes of the 64-bit context slots.
        body += "  and ebx, 0xFF\n  and ebp, 0xFF\n  and r10d, 0xFF\n"
    elif width == _WORD_WIDTH_BITS:
        # 16-bit compare: same, masked to the low word (the sign bit keys off bit 15).
        body += "  and ebx, 0xFFFF\n  and ebp, 0xFFFF\n  and r10d, 0xFFFF\n"
    body += _synth_flags_asm(width, synth_mode, flag_variant)
    body += f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _shift_handler_asm(handler_key: str, key: str, field_perm: int = 0, shift_variant: int = 0) -> str:
    """Assembly body for a shl/shr/sar handler (count is an immediate in cl)."""
    mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    off = shift_offsets(field_perm)
    body = (
        f"  movzx r8d, byte ptr [rsi+{off['slot']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx ecx, byte ptr [rsi+{off['count']}]\n  xor cl, {key}\n  xor cl, r13b\n"
    )
    if width == _QWORD_WIDTH_BITS:
        body += f"  mov rax, qword ptr [rsp+r8*8]\n  {mnemonic} rax, cl\n"
    else:
        body += f"  mov eax, dword ptr [rsp+r8*8]\n  {mnemonic} eax, cl\n"
    # Move the result to r11 (a flag-neutral mov) so the flag capture runs on the
    # shift's flags before the register-file cipher encrypts the slot store; the store
    # is emitted after the capture so the encrypting xor never clobbers those flags.
    return (
        body
        + "  mov r11, rax\n"
        + shift_flag_capture_asm(shift_variant, _FLAGS_OFFSET)
        + "  mov qword ptr [rsp+r8*8], r11\n"
        + "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _imul_handler_asm(handler_key: str, key: str, field_perm: int = 0) -> str:
    """Assembly body for a two-operand register imul handler."""
    width = int(handler_key.split("_")[1])
    # Two register slots - the same field shape as a register-form arithmetic op.
    off = op_offsets(False, width, field_perm)
    body = (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
    )
    # Load the source operand into r11 via a mov (so the register-file cipher decrypts
    # it like any slot read - a direct memory-operand imul would not be ciphered) and
    # store the product after the flag capture so the encrypting xor keeps the flags.
    if width == _QWORD_WIDTH_BITS:
        body += "  mov rax, qword ptr [rsp+r8*8]\n  mov r11, qword ptr [rsp+r9*8]\n  imul rax, r11\n"
    else:
        body += "  mov eax, dword ptr [rsp+r8*8]\n  mov r11d, dword ptr [rsp+r9*8]\n  imul eax, r11d\n"
    return (
        body + f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
        "  mov qword ptr [rsp+r8*8], rax\n  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _not_handler_asm(handler_key: str, key: str) -> str:
    """Assembly body for ``not reg`` (bitwise complement, no flags).

    The slot value is loaded into rax and the width-sized complement is taken on the
    matching sub-register: a 64-bit ``not`` complements the whole cell, a 32-bit one
    zero-extends, and the 8/16-bit forms complement only the low byte/word and leave
    the upper bytes of the loaded cell untouched - all exactly as the native op. ``not``
    sets no flags, so the flags slot is not touched.
    """
    width = int(handler_key.split("_")[1])
    sub = {8: "al", 16: "ax", 32: "eax", 64: "rax"}[width]
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        "  mov rax, qword ptr [rsp+r8*8]\n"
        f"  not {sub}\n"
        "  mov qword ptr [rsp+r8*8], rax\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _div_handler_asm(handler_key: str, key: str) -> str:
    """Assembly body for ``div reg`` / ``idiv reg`` (register divisor).

    Reads three slot indices (divisor, then the implicit rax and rdx, emitted as
    permuted operand bytes): the divisor is loaded into r11 first so it survives even
    when it aliases rax or rdx, then the dividend halves are loaded into rax/rdx and
    the real division runs. Quotient (rax) and remainder (rdx) are written back to
    their slots. Division leaves the flags undefined, so none are captured; a divide
    by zero faults exactly as the native op.
    """
    _, signedness, width_text = handler_key.split("_")
    width = int(width_text)
    mnemonic = "idiv" if signedness == "s" else "div"
    divisor = "r11" if width == _QWORD_WIDTH_BITS else "r11d"
    ax = "rax" if width == _QWORD_WIDTH_BITS else "eax"
    dx = "rdx" if width == _QWORD_WIDTH_BITS else "edx"
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        f"  movzx r10d, byte ptr [rsi+3]\n  xor r10b, {key}\n  xor r10b, r13b\n"
        f"  mov {divisor}, {'qword' if width == _QWORD_WIDTH_BITS else 'dword'} ptr [rsp+r8*8]\n"
        f"  mov {ax}, {'qword' if width == _QWORD_WIDTH_BITS else 'dword'} ptr [rsp+r9*8]\n"
        f"  mov {dx}, {'qword' if width == _QWORD_WIDTH_BITS else 'dword'} ptr [rsp+r10*8]\n"
        f"  {mnemonic} {divisor}\n"
        "  mov qword ptr [rsp+r9*8], rax\n"
        "  mov qword ptr [rsp+r10*8], rdx\n"
        "  add rsi, 4\n  jmp vm_dispatch\n"
    )


def _cqo_handler_asm(handler_key: str, key: str) -> str:
    """Assembly body for ``cqo`` / ``cdq`` (sign-extend rax into rdx, no flags).

    Reads the implicit rax and rdx slot indices, loads rax, sign-extends it into rdx
    with the real instruction, and stores rdx back (rax is unchanged).
    """
    width = int(handler_key.split("_")[1])
    return (
        f"  movzx r9d, byte ptr [rsi+1]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        f"  movzx r10d, byte ptr [rsi+2]\n  xor r10b, {key}\n  xor r10b, r13b\n"
        + (
            "  mov rax, qword ptr [rsp+r9*8]\n  cqo\n"
            if width == _QWORD_WIDTH_BITS
            else "  mov eax, dword ptr [rsp+r9*8]\n  cdq\n"
        )
        + "  mov qword ptr [rsp+r10*8], rdx\n"
        "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _bt_handler_asm(handler_key: str, key: str) -> str:
    """Assembly body for ``bt reg, reg`` / ``bt reg, imm`` (bit test).

    Loads the value and the bit index (from a slot for the register form, or the
    unmasked immediate byte for the immediate form) into registers, then runs the
    real ``bt`` and merges its CF into the flags slot: the program's other flags are
    loaded first so ZF stays put and the architecturally-undefined SF/OF/AF/PF keep a
    defined (program) value, exactly what the native op leaves. Nothing is written
    back to a register slot.
    """
    _, mode, width_text = handler_key.split("_")
    width = int(width_text)
    is_immediate = mode == "i"
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
    if is_immediate:
        body += f"  movzx r10d, byte ptr [rsi+2]\n  xor r10b, {key}\n  xor r10b, r13b\n"
    else:
        body += f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        body += "  mov r10, qword ptr [rsp+r9*8]\n"
    body += "  mov rax, qword ptr [rsp+r8*8]\n" if width == _QWORD_WIDTH_BITS else "  mov eax, dword ptr [rsp+r8*8]\n"
    body += f"  push qword ptr [rsp+{_FLAGS_OFFSET}]\n  popfq\n"
    body += "  bt rax, r10\n" if width == _QWORD_WIDTH_BITS else "  bt eax, r10d\n"
    body += f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
    return body + "  add rsi, 3\n  jmp vm_dispatch\n"


def _bswap_handler_asm(handler_key: str, key: str) -> str:
    """Assembly body for ``bswap reg`` (byte-order reversal, no flags, 32/64-bit).

    The slot value is loaded into rax and the width-sized byte swap is taken on the
    matching sub-register: a 32-bit ``bswap`` zero-extends, a 64-bit one reverses all
    eight bytes, both exactly as the native op. ``bswap`` sets no flags.
    """
    width = int(handler_key.split("_")[1])
    sub = "eax" if width == _DWORD_WIDTH_BITS else "rax"
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        "  mov rax, qword ptr [rsp+r8*8]\n"
        f"  bswap {sub}\n"
        "  mov qword ptr [rsp+r8*8], rax\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _push_handler_asm(key: str, rsp_off: int) -> str:
    """Assembly body for ``push reg`` against the relocated virtual stack.

    The program's rsp lives in a frame slot (relocated below the VM frame at
    entry); decrement it by 8 and write the register value there. push sets no
    flags.
    """
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        "  mov rax, qword ptr [rsp+r8*8]\n"
        f"  mov r9, qword ptr [rsp+{rsp_off}]\n  sub r9, 8\n  mov qword ptr [rsp+{rsp_off}], r9\n"
        "  mov qword ptr [r9], rax\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _pop_handler_asm(key: str, rsp_off: int) -> str:
    """Assembly body for ``pop reg`` against the relocated virtual stack.

    Read the value at the program's rsp BEFORE incrementing it (matching the
    architectural order), then store it into the destination slot. pop sets no
    flags. The destination is never rsp (rejected at decode), so there is no
    aliasing between the slot write and the rsp-slot update.
    """
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  mov r9, qword ptr [rsp+{rsp_off}]\n  mov rax, qword ptr [r9]\n"
        f"  add r9, 8\n  mov qword ptr [rsp+{rsp_off}], r9\n"
        "  mov qword ptr [rsp+r8*8], rax\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _rspadj_handler_asm(handler_key: str, key_dword: str, rsp_off: int) -> str:
    """Assembly body for ``add rsp, imm`` / ``sub rsp, imm`` (frame allocation).

    Adjusts the program's relocated rsp slot by a sign-extended imm32. The flags
    are captured for consistency with the other arithmetic handlers; they reflect
    the relocated stack pointer rather than the native one, which is harmless
    because stack-adjustment flags are architecturally dead in compiled code (no
    branch ever consumes them).
    """
    mnemonic = handler_key.split("_")[1]
    return (
        f"  mov eax, dword ptr [rsi+1]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
        + _unmask_dword("r11")
        + "  movsxd rax, eax\n"
        f"  mov r11, qword ptr [rsp+{rsp_off}]\n  {mnemonic} r11, rax\n"
        f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
        f"  mov qword ptr [rsp+{rsp_off}], r11\n"
        "  add rsi, 5\n  jmp vm_dispatch\n"
    )


def _mov_from_rsp_handler_asm(key: str, rsp_off: int) -> str:
    """Assembly body for ``mov reg, rsp`` (copy the relocated rsp into a slot)."""
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  mov rax, qword ptr [rsp+{rsp_off}]\n"
        "  mov qword ptr [rsp+r8*8], rax\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _mov_to_rsp_handler_asm(key: str, rsp_off: int) -> str:
    """Assembly body for ``mov rsp, reg`` (restore the relocated rsp from a slot)."""
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        "  mov rax, qword ptr [rsp+r8*8]\n"
        f"  mov qword ptr [rsp+{rsp_off}], rax\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _leave_handler_asm(key: str, rsp_off: int) -> str:
    """Assembly body for ``leave`` (``mov rsp, rbp`` then ``pop rbp``).

    The rbp slot holds the saved frame pointer; rsp is set to it, then the saved
    rbp is popped off the relocated stack and rsp incremented. No flags.
    """
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        "  mov rax, qword ptr [rsp+r8*8]\n"
        f"  mov qword ptr [rsp+{rsp_off}], rax\n"
        "  mov r9, rax\n  mov rax, qword ptr [r9]\n  add r9, 8\n"
        f"  mov qword ptr [rsp+{rsp_off}], r9\n"
        "  mov qword ptr [rsp+r8*8], rax\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _pushi_handler_asm(key_qword: str, rsp_off: int) -> str:
    """Assembly body for ``push imm`` (sign-extended 64-bit immediate)."""
    return (
        f"  mov rax, qword ptr [rsi+1]\n  mov r10, {key_qword}\n  xor rax, r10\n"
        + _unmask_qword("r10", "r11")
        + f"  mov r9, qword ptr [rsp+{rsp_off}]\n  sub r9, 8\n  mov qword ptr [rsp+{rsp_off}], r9\n"
        "  mov qword ptr [r9], rax\n"
        "  add rsi, 9\n  jmp vm_dispatch\n"
    )


def _imul3_handler_asm(handler_key: str, key: str, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for a three-operand ``imul reg, reg, imm`` handler.

    The immediate lives encrypted in the bytecode stream, so the multiply is
    done by a register-form ``imul`` against the decrypted, sign-extended
    immediate rather than a literal imm operand. The result and CF/OF match the
    native three-operand imul (same low-half product, same overflow).
    """
    width = int(handler_key.split("_")[1])
    off = imul3_offsets(field_perm)
    body = (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
    )
    body += f"  mov eax, dword ptr [rsi+{off['imm']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n" + _unmask_dword(
        "r11"
    )
    if width == _QWORD_WIDTH_BITS:
        body += "  movsxd r10, eax\n  mov rax, qword ptr [rsp+r9*8]\n  imul rax, r10\n"
    else:
        body += "  mov r10d, dword ptr [rsp+r9*8]\n  imul r10d, eax\n  mov rax, r10\n"
    return (
        body + f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
        "  mov qword ptr [rsp+r8*8], rax\n  add rsi, 7\n  jmp vm_dispatch\n"
    )
