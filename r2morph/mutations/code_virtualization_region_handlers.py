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

from r2morph.mutations.code_virtualization_layout import (
    field_offsets,
    idx_offsets,
    imul3_offsets,
    mem_offsets,
    op_offsets,
    shift_offsets,
)
from r2morph.mutations.code_virtualization_mba import _mba_add, _mba_add_r10_rax, _op_mba_compute
from r2morph.mutations.code_virtualization_region_models import _DWORD_BROADCAST, _QWORD_BROADCAST

# Stack frame: 16 GP context slots in [0x00, 0x80), the captured RFLAGS at 0x80,
# the self-checksum byte at 0x88, the 16 XMM save slots (16 bytes each) in
# [0x100, 0x200), and the System V red zone preserved in the top [0x200, 0x280).
# The XMM slots sit where the red zone used to be; growing the frame rode the red
# zone up to the new top, and since nothing reads it by offset the only effect is
# the larger reservation. Every GP-slot offset (rsp + slot*8) is unchanged, so the
# handler addressing is untouched.
_FRAME_SIZE = 0x280
_FLAGS_OFFSET = 0x80
# Base of the 16 XMM save slots (16 bytes each); slot i lives at
# [rsp + _XMM_SAVE_OFFSET + i*16). Spilled/reloaded only when a region carries FP.
_XMM_SAVE_OFFSET = 0x100
# The program's virtual stack is relocated this far below the VM frame so the
# function's own push/pop traffic never collides with the spilled context. Must
# be 16-aligned and strictly greater than _FRAME_SIZE so the relocated stack
# stays below the frame.
_GUARD = 0x300


def xmm_spill_asm() -> str:
    """Spill all 16 XMM registers into their frame slots (movups: no alignment
    requirement, so it is correct whatever rsp's 16-alignment happens to be)."""
    return "".join(f"  movups [rsp + {_XMM_SAVE_OFFSET + i * 16}], xmm{i}\n" for i in range(16))


def xmm_reload_asm() -> str:
    """Reload all 16 XMM registers from their frame slots before leaving the VM."""
    return "".join(f"  movups xmm{i}, [rsp + {_XMM_SAVE_OFFSET + i * 16}]\n" for i in range(16))


def _fp_memory_handler_asm(handler_key: str, key: int, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for a scalar-FP load/store handler (``movsd``/``movss`` xmm
    <-> [base+disp]).

    The shared address prologue decrypts the operand fields - here the "register"
    field is the XMM index (0-15), not a GP slot - and computes the effective
    address into r10. The handler moves between program memory and the XMM save
    slot via the real xmm0 (free scratch during VM execution, since every program
    XMM lives in a slot). ``movsd``/``movss`` loads zero the high lanes of the
    destination, matching x86-64, so the full 16-byte slot is rewritten. FP moves
    set no flags, so the captured-flags slot is untouched.
    """
    kind, width_text = handler_key.split("_")
    width = int(width_text)
    move = "movsd" if width == 64 else "movss"
    mem = "qword" if width == 64 else "dword"
    body, advance = _mem_address_asm(False, key, key_dword, field_perm)
    # r8 holds the XMM index; scale to the 16-byte slot stride (no *16 index scale
    # exists, so shift into r11 and address base+index+disp at scale 1).
    body += "  mov r11, r8\n  shl r11, 4\n"
    if kind == "fpload":
        body += f"  {move} xmm0, {mem} ptr [r10]\n  movups [rsp + r11 + {_XMM_SAVE_OFFSET}], xmm0\n"
    else:
        body += f"  movups xmm0, [rsp + r11 + {_XMM_SAVE_OFFSET}]\n  {move} {mem} ptr [r10], xmm0\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _fp_arith_handler_asm(handler_key: str, key: int) -> str:
    """Assembly body for a scalar-FP register-register arithmetic handler
    (``addsd``/``subsd``/``mulsd``/``divsd`` and their ``ss`` forms).

    The two operand bytes are XMM indices (un-masked with the key and the stream
    position like every operand); both registers are loaded from their save slots
    into the real xmm0/xmm1 (free scratch during VM execution), the scalar op runs
    on the low lane leaving the high lanes of the destination untouched, and the
    result is written back to the destination's slot. FP arithmetic sets no flags,
    so the captured-flags slot is untouched.
    """
    _, mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    instr = mnemonic + ("sd" if width == 64 else "ss")
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n"
        f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  movups xmm1, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n"
        f"  {instr} xmm0, xmm1\n"
        f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
        "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _fp_arith_mem_handler_asm(handler_key: str, key: int, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for scalar-FP arithmetic with a ``[base+disp]`` memory source
    (``addsd xmm, [base+disp]`` and the sub/mul/div, ss forms).

    The shared memory-address prologue decrypts the operand fields - here the
    "register" field is the destination XMM index - and computes the effective
    address into r10. The destination is loaded from its save slot, the scalar op
    runs against the memory operand on the low lane (upper lanes preserved), and the
    result is written back. FP arithmetic sets no flags.
    """
    _, mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    instr = mnemonic + ("sd" if width == 64 else "ss")
    mem = "qword" if width == 64 else "dword"
    body, advance = _mem_address_asm(False, key, key_dword, field_perm)
    body += f"  shl r8, 4\n  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n"
    body += f"  {instr} xmm0, {mem} ptr [r10]\n  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _fp_convert_handler_asm(handler_key: str, key: int) -> str:
    """Assembly body for an int<->float conversion handler with a 64-bit GP
    operand (``cvtsi2sd/ss`` int->float, ``cvttsd2si/ss`` float->int, truncating).

    Both operands are un-masked with the key and stream position. ``cvti2f`` reads
    the GP source from its (slot_perm) frame slot and converts into the scalar low
    lane of the destination XMM, preserving its upper lane (loaded from the slot,
    since cvtsi2sd is a scalar op). ``cvtf2i`` truncates the source XMM's low lane
    into the GP destination's frame slot. Conversions set no flags.
    """
    kind, width_text = handler_key.split("_")
    width = int(width_text)
    if kind == "cvti2f":
        instr = "cvtsi2sd" if width == 64 else "cvtsi2ss"
        # byte1 = XMM index (r8, scaled to the 16-byte slot), byte2 = GP slot (r9).
        return (
            f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n  xor r9b, r13b\n"
            "  shl r8, 4\n  mov rax, qword ptr [rsp + r9*8]\n"
            f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  {instr} xmm0, rax\n"
            f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
            "  add rsi, 3\n  jmp vm_dispatch\n"
        )
    instr = "cvttsd2si" if width == 64 else "cvttss2si"
    # byte1 = GP slot (r9), byte2 = XMM index (r8, scaled to the 16-byte slot).
    return (
        f"  movzx r9d, byte ptr [rsi+1]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        f"  movzx r8d, byte ptr [rsi+2]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  shl r8, 4\n  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  {instr} rax, xmm0\n"
        "  mov qword ptr [rsp + r9*8], rax\n"
        "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _fp_compare_handler_asm(handler_key: str, key: int) -> str:
    """Assembly body for a scalar-FP register-register compare
    (``ucomisd``/``comisd`` and the ``ss`` forms).

    Both operands are loaded from their XMM save slots into the real xmm0/xmm1; the
    real compare runs (no MBA equivalent exists for an FP ordered compare) and its
    flags - ZF/PF/CF, faithfully including the unordered/NaN case - are captured
    into the frame's flags slot with the same pushfq/pop idiom the GP handlers use,
    so the existing branch handler consumes them unchanged.
    """
    instr = handler_key.split("_", 1)[1]
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n"
        f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  movups xmm1, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n"
        f"  {instr} xmm0, xmm1\n"
        f"  pushfq\n  pop qword ptr [rsp + {_FLAGS_OFFSET}]\n"
        "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _fp_move_handler_asm(handler_key: str, key: int) -> str:
    """Assembly body for a register-register xmm move (full 128-bit copy, or a
    scalar movsd/movss that preserves the destination's upper lane(s)).

    Both operand bytes are XMM indices. The full copy reads the source slot and
    writes it whole to the destination slot; the scalar copy loads the destination
    slot first so the real movsd/movss preserves its high lanes (unlike the memory
    load forms, which zero them), then writes the merged value back. No flags.
    """
    mode = handler_key.split("_", 1)[1]
    decode = (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n"
    )
    if mode == "full":
        body = f"  movups xmm0, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
    else:
        instr = "movsd" if mode == "sd" else "movss"
        body = (
            f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  movups xmm1, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n"
            f"  {instr} xmm0, xmm1\n  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
        )
    return decode + body + "  add rsi, 3\n  jmp vm_dispatch\n"


def _unmask_dword(scratch: str) -> str:
    """Un-mask a dword immediate/displacement (in eax) with the item's stream
    position: r13b holds it from the dispatch, broadcast to 32 bits. ``scratch``
    is a register free at the call site (typically the just-used key temp)."""
    return f"  movzx {scratch}d, r13b\n  imul {scratch}d, {scratch}d, {hex(_DWORD_BROADCAST)}\n  xor eax, {scratch}d\n"


def _unmask_qword(scratch: str, scratch2: str) -> str:
    """Un-mask a qword immediate (in rax) with the item's stream position (r13b),
    broadcast to 64 bits. Both scratch registers must be free at the call site."""
    return f"  movzx {scratch}, r13b\n  mov {scratch2}, {hex(_QWORD_BROADCAST)}\n  imul {scratch}, {scratch2}\n  xor rax, {scratch}\n"


def _op_handler_asm(handler_key: str, key: int, key_qword: str, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for an arithmetic/mov handler (decrypts, applies, captures flags)."""
    _, mnemonic, mode, width_text = handler_key.split("_")
    width = int(width_text)
    is_immediate = mode == "i"
    off = field_offsets(handler_key, field_perm)
    body = f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
    if is_immediate and width == 64:
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
        body += "  mov rax, qword ptr [rsp+r9*8]\n" if width == 64 else "  mov eax, dword ptr [rsp+r9*8]\n"
        advance = 3
    if mnemonic == "mov":
        body += "  mov qword ptr [rsp+r8*8], rax\n"
    elif width == 64:
        body += f"  {mnemonic} qword ptr [rsp+r8*8], rax\n  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
    else:
        body += (
            f"  mov r11d, dword ptr [rsp+r8*8]\n  {mnemonic} r11d, eax\n"
            f"  mov qword ptr [rsp+r8*8], r11\n  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
        )
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _op_mba_handler_asm(handler_key: str, key: int, key_qword: str, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for a flag-dead ``add``/``sub`` handler.

    The region's flag-liveness analysis proved this op's flags are never read, so
    the result is computed with a mixed boolean-arithmetic rewrite (no literal
    add/sub) and no flags are captured. ``sub a, b`` is folded as ``add a, -b``.
    The destination is loaded into r10, the source/immediate into rax, and the
    MBA fold leaves the result in r10. A 32-bit destination zero-extends.
    """
    _, mnemonic, mode, width_text = handler_key.split("_")
    width = int(width_text)
    is_immediate = mode == "i"
    off = field_offsets(handler_key, field_perm)
    body = f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
    if is_immediate and width == 64:
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
        body += "  mov rax, qword ptr [rsp+r9*8]\n" if width == 64 else "  mov eax, dword ptr [rsp+r9*8]\n"
        advance = 3
    # sub a, b == add a, (-b): negate the source, then the same MBA add fold.
    if mnemonic == "sub":
        body += "  neg rax\n"
    body += "  mov r10, qword ptr [rsp+r8*8]\n" if width == 64 else "  mov r10d, dword ptr [rsp+r8*8]\n"
    body += _op_mba_compute(mnemonic, key)
    if width == 64:
        body += "  mov qword ptr [rsp+r8*8], r10\n"
    else:
        body += "  mov r10d, r10d\n  mov qword ptr [rsp+r8*8], r10\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _synth_flags_asm(width: int, mode: str) -> str:
    """Branchlessly synthesize the readable flags of ``a <op> b`` into r11 (a RFLAGS
    image), reading a in rbx, b in rbp and the result in r10.

    ``mode`` is ``"add"``, ``"sub"`` or ``"logic"`` (and/or/xor/test). No flag-setting
    native op spells out the operation: each of SF, ZF and PF - plus CF and OF for
    add/sub (a logic op clears both) - is computed from a, b and the result with pure
    and/or/xor/shift/neg, whose own flags are discarded. AF is read by no conditional
    jump, so it is omitted. The formulas are verified bit-for-bit against the CPU over
    all operand edge cases for add, sub and and/test at 32- and 64-bit widths.
    rcx/rax/r9 are scratch; r8 (the destination slot) is preserved for any result store.
    """
    sh = width - 1
    a, b, r = ("rbx", "rbp", "r10") if width == 64 else ("ebx", "ebp", "r10d")
    c, t, u = ("rcx", "rax", "r9") if width == 64 else ("ecx", "eax", "r9d")
    lines = ["  xor r11d, r11d\n"]
    # ZF (bit 6): set when the result is zero.
    lines.append(
        f"  mov {c}, {r}\n  neg {c}\n  or {c}, {r}\n  shr {c}, {sh}\n  and {c}, 1\n  xor {c}, 1\n  shl {c}, 6\n  or r11, rcx\n"
    )
    # SF (bit 7): the result's sign bit.
    lines.append(f"  mov {c}, {r}\n  shr {c}, {sh}\n  and {c}, 1\n  shl {c}, 7\n  or r11, rcx\n")
    if mode == "add":
        # CF (bit 0): carry-out. OF (bit 11): signed overflow.
        lines.append(
            f"  mov {c}, {a}\n  and {c}, {b}\n  mov {u}, {a}\n  or {u}, {b}\n  mov {t}, {r}\n  not {t}\n  and {u}, {t}\n  or {c}, {u}\n  shr {c}, {sh}\n  and {c}, 1\n  or r11, rcx\n"
        )
        lines.append(
            f"  mov {c}, {a}\n  xor {c}, {r}\n  mov {u}, {b}\n  xor {u}, {r}\n  and {c}, {u}\n  shr {c}, {sh}\n  and {c}, 1\n  shl {c}, 11\n  or r11, rcx\n"
        )
    elif mode == "sub":
        # CF (bit 0): borrow. OF (bit 11): signed overflow.
        lines.append(
            f"  mov {c}, {a}\n  not {c}\n  and {c}, {b}\n  mov {u}, {a}\n  not {u}\n  or {u}, {b}\n  and {u}, {r}\n  or {c}, {u}\n  shr {c}, {sh}\n  and {c}, 1\n  or r11, rcx\n"
        )
        lines.append(
            f"  mov {c}, {a}\n  xor {c}, {b}\n  mov {u}, {a}\n  xor {u}, {r}\n  and {c}, {u}\n  shr {c}, {sh}\n  and {c}, 1\n  shl {c}, 11\n  or r11, rcx\n"
        )
    # mode == "logic": CF and OF are cleared by the operation, so nothing to add.
    # PF (bit 2): even parity of the result's low byte.
    lines.append(
        f"  movzx ecx, r10b\n  mov {u}, {c}\n  shr {u}, 4\n  xor {c}, {u}\n  mov {u}, {c}\n  shr {u}, 2\n  xor {c}, {u}\n  mov {u}, {c}\n  shr {u}, 1\n  xor {c}, {u}\n  not {c}\n  and ecx, 1\n  shl ecx, 2\n  or r11, rcx\n"
    )
    return "".join(lines)


def _op_synth_handler_asm(handler_key: str, key: int, key_qword: str, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for a flag-LIVE ``add``/``sub`` handler.

    Where ``_op_mba_handler_asm`` serves the flag-dead case (no flag capture), this
    serves ops whose flags a later branch reads: it computes the result with the
    same MBA fold (no literal add/sub) AND synthesizes the readable flags by hand
    (no ``pushfq`` of a literal op), so the handler contains no flag-setting native
    arithmetic at all. The original operands are saved in rbx/rbp before the MBA
    (which clobbers only r10/rax/rcx) so the synthesis can read a, b and the result.
    """
    _, mnemonic, mode, width_text = handler_key.split("_")
    width = int(width_text)
    is_immediate = mode == "i"
    off = field_offsets(handler_key, field_perm)
    body = f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
    if is_immediate and width == 64:
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
        body += "  mov rax, qword ptr [rsp+r9*8]\n" if width == 64 else "  mov eax, dword ptr [rsp+r9*8]\n"
        advance = 3
    # Save the original operands (b before any negation, a before the MBA) so the
    # flag synthesis can read them alongside the result.
    body += "  mov rbp, rax\n"
    body += "  mov r10, qword ptr [rsp+r8*8]\n" if width == 64 else "  mov r10d, dword ptr [rsp+r8*8]\n"
    body += "  mov rbx, r10\n"
    if mnemonic == "sub":
        body += "  neg rax\n"
    body += _op_mba_compute(mnemonic, key)
    if width == 32:
        body += "  mov r10d, r10d\n"
    # add/sub keep their arithmetic flags; xor/and/or clear CF and OF (logic mode).
    body += _synth_flags_asm(width, mnemonic if mnemonic in ("add", "sub") else "logic")
    body += f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    body += "  mov qword ptr [rsp+r8*8], r10\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _mem_address_asm(riprel: bool, key: int, key_dword: str, field_perm: int = 0) -> tuple[str, int]:
    """Shared head of every memory handler: decrypt the register slot into r8
    and compute the effective address into r10.

    For the rip-relative form the address is the bytecode base (r15) plus the
    stored signed offset; otherwise it is a frame-slot base value plus a signed
    displacement. The operand fields are read at this build's permuted offsets
    (the encoder emits them in the same order), so the layout differs per build.
    Returns the assembly and the number of bytes to advance rsi by.
    """
    off = mem_offsets(riprel, field_perm)
    body = f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
    if riprel:
        return (
            body
            + f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
            + _unmask_dword("r11")
            + "  movsxd rax, eax\n  mov r10, r15\n"
            + _mba_add_r10_rax(key)
        ), 6
    return (
        body + f"  movzx r9d, byte ptr [rsi+{off['base']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
        + _unmask_dword("r11")
        + "  movsxd rax, eax\n  mov r10, qword ptr [rsp+r9*8]\n"
        + _mba_add_r10_rax(key)
    ), 7


def _memory_handler_asm(handler_key: str, key: int, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for a load/store handler (``mov`` reg <-> [base+disp]).

    The base value is read from its frame slot (so rsp resolves to the captured
    original rsp, and any base updated earlier in the run is seen at its current
    value), the signed displacement is added, and the qword/dword is moved. A
    32-bit load zero-extends, matching x86-64. ``mov`` sets no flags, so the
    captured-flags slot is untouched.
    """
    kind, width_text = handler_key.split("_")
    width = int(width_text)
    body, advance = _mem_address_asm(False, key, key_dword, field_perm)
    if kind == "load":
        load = "  mov rax, qword ptr [r10]\n" if width == 64 else "  mov eax, dword ptr [r10]\n"
        body += load + "  mov qword ptr [rsp+r8*8], rax\n"
    elif width == 64:
        body += "  mov rax, qword ptr [rsp+r8*8]\n  mov qword ptr [r10], rax\n"
    else:
        body += "  mov eax, dword ptr [rsp+r8*8]\n  mov dword ptr [r10], eax\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _riprel_handler_asm(handler_key: str, key: int, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for a rip-relative load/store handler.

    The target is recomputed as bytecode-base (r15) plus the stored signed
    offset, so it reaches the same global the original ``[rip+disp]`` did and
    stays correct under rebasing (the global and the VM share one image).
    """
    _, sub, width_text = handler_key.split("_")
    width = int(width_text)
    body, advance = _mem_address_asm(True, key, key_dword, field_perm)
    if sub == "load":
        load = "  mov rax, qword ptr [r10]\n" if width == 64 else "  mov eax, dword ptr [r10]\n"
        body += load + "  mov qword ptr [rsp+r8*8], rax\n"
    elif width == 64:
        body += "  mov rax, qword ptr [rsp+r8*8]\n  mov qword ptr [r10], rax\n"
    else:
        body += "  mov eax, dword ptr [rsp+r8*8]\n  mov dword ptr [r10], eax\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _cmp_memory_handler_asm(handler_key: str, key: int, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for ``cmp reg, [mem]`` (computes the address, synthesizes flags).

    The memory address comes from a frame-slot base plus displacement (``cmpmem``)
    or the bytecode base plus a stored offset (``cmpriprel``). The comparison is the
    register minus the loaded memory value, computed with the MBA fold and its flags
    synthesized by hand (no literal cmp, no pushfq), exactly like the register/
    immediate compare handler; nothing is written back.
    """
    parts = handler_key.split("_")
    riprel = parts[0] == "cmpriprel"
    width = int(parts[-1])
    body, advance = _mem_address_asm(riprel, key, key_dword, field_perm)
    # a = the register operand, b = the memory operand; compute a - b via MBA.
    if width == 64:
        body += "  mov rbx, qword ptr [rsp+r8*8]\n  mov rax, qword ptr [r10]\n"
    else:
        body += "  mov ebx, dword ptr [rsp+r8*8]\n  mov eax, dword ptr [r10]\n"
    body += "  mov rbp, rax\n  neg rax\n  mov r10, rbx\n"
    body += _op_mba_compute("add", key)
    if width == 32:
        body += "  mov r10d, r10d\n"
    body += _synth_flags_asm(width, "sub")
    body += f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _op_memdst_handler_asm(handler_key: str, key: int, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for ``<op> [mem], reg`` (memory is the read-modify-write
    destination, the register is the source).

    The address is computed with the shared prologue and kept in r12 (free scratch)
    so the result can be written back to memory after the MBA fold; the memory value
    is a, the register is b, and the flags are synthesized (no literal op, no pushfq).
    """
    parts = handler_key.split("_")
    riprel = parts[0] == "opmemdstrip"
    mnemonic, width = parts[1], int(parts[2])
    body, advance = _mem_address_asm(riprel, key, key_dword, field_perm)
    body += "  mov r12, r10\n"
    if width == 64:
        body += "  mov rbx, qword ptr [r12]\n  mov rax, qword ptr [rsp+r8*8]\n"
    else:
        body += "  mov ebx, dword ptr [r12]\n  mov eax, dword ptr [rsp+r8*8]\n"
    body += "  mov rbp, rax\n"
    if mnemonic == "sub":
        body += "  neg rax\n"
    body += "  mov r10, rbx\n"
    body += _op_mba_compute(mnemonic, key)
    if width == 32:
        body += "  mov r10d, r10d\n"
    body += _synth_flags_asm(width, mnemonic if mnemonic in ("add", "sub") else "logic")
    body += f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    if width == 64:
        body += "  mov qword ptr [r12], r10\n"
    else:
        body += "  mov dword ptr [r12], r10d\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _movx_handler_asm(handler_key: str, key: int, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for ``movzx/movsx reg, byte|word [base+disp]``.

    The address is computed with the shared prologue, then the byte or word is
    zero- or sign-extended into the destination slot. movzx always zero-extends
    the same regardless of destination width; movsx's extension target depends
    on whether the destination is 32- or 64-bit. movzx/movsx set no flags.
    """
    _, ext, src_size_text, dst_width_text = handler_key.split("_")
    body, advance = _mem_address_asm(False, key, key_dword, field_perm)
    return body + _movx_extend_asm(ext, int(src_size_text), int(dst_width_text), advance)


def _movx_extend_asm(ext: str, src_size: int, dst_width: int, advance: int) -> str:
    """The extend-from-[r10]-into-the-slot tail shared by the movzx/movsx handlers."""
    size_word = "byte" if src_size == 8 else "word"
    if ext == "z":
        load = f"  movzx eax, {size_word} ptr [r10]\n"
    elif dst_width == 64:
        load = f"  movsx rax, {size_word} ptr [r10]\n"
    else:
        load = f"  movsx eax, {size_word} ptr [r10]\n"
    return load + f"  mov qword ptr [rsp+r8*8], rax\n  add rsi, {advance}\n  jmp vm_dispatch\n"


def _movx_indexed_handler_asm(handler_key: str, key: int, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for ``movzx/movsx reg, byte|word [base+index*scale+disp]``."""
    _, ext, src_size_text, dst_width_text = handler_key.split("_")
    body, advance = _indexed_address_asm(key, key_dword, field_perm)
    return body + _movx_extend_asm(ext, int(src_size_text), int(dst_width_text), advance)


def _incdec_handler_asm(handler_key: str, key: int) -> str:
    """Assembly body for ``inc reg`` / ``dec reg``.

    inc/dec leave CF untouched (unlike add/sub by one), so the result is computed
    with the MBA fold (a +/- 1) and OF/SF/ZF/PF are synthesized exactly like add/sub
    with the second operand 1, while CF is carried over unchanged from the captured
    flags slot - no literal inc/dec and no pushfq. A 32-bit form zero-extends.
    """
    _, mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
    body += "  mov r10, qword ptr [rsp+r8*8]\n" if width == 64 else "  mov r10d, dword ptr [rsp+r8*8]\n"
    body += "  mov rbx, r10\n  mov ebp, 1\n"
    if mnemonic == "inc":
        body += "  mov eax, 1\n"
        synth_mode = "add"
    else:
        body += "  mov rax, -1\n"
        synth_mode = "sub"
    body += _op_mba_compute("add", key)  # r10 = a +/- 1
    if width == 32:
        body += "  mov r10d, r10d\n"
    body += _synth_flags_asm(width, synth_mode)
    # inc/dec preserve CF: drop the synthesized carry (bit 0) and OR in the program's.
    body += f"  and r11, -2\n  mov rcx, qword ptr [rsp+{_FLAGS_OFFSET}]\n  and ecx, 1\n  or r11, rcx\n"
    body += f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    body += "  mov qword ptr [rsp+r8*8], r10\n"
    return body + "  add rsi, 2\n  jmp vm_dispatch\n"


def _indexed_address_asm(key: int, key_dword: str, field_perm: int = 0) -> tuple[str, int]:
    """Shared head of every indexed memory handler: decrypt the register slot
    into r8 and compute ``base + index*scale + disp`` into r10.

    The index is read from its slot and shifted by the encoded scale log2, then
    the base and displacement are added. The operand fields are read at this
    build's permuted offsets (the encoder emits them in the same order). Returns
    the assembly and the rsi advance (the bytecode item width).
    """
    off = idx_offsets(False, field_perm)
    return (
        f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['base']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        f"  movzx r11d, byte ptr [rsi+{off['index']}]\n  xor r11b, {key}\n  xor r11b, r13b\n"
        f"  movzx ecx, byte ptr [rsi+{off['shift']}]\n  xor cl, {key}\n  xor cl, r13b\n"
        f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r10d, {key_dword}\n  xor eax, r10d\n"
        + _unmask_dword("r10")
        + "  movsxd rax, eax\n  mov r10, qword ptr [rsp+r11*8]\n  shl r10, cl\n"
        # Fold the base with MBA too (r11 holds the base value), so neither the
        # base nor the displacement add is a literal add. rcx and r11 are free
        # here (the index slot and scale were already consumed).
        "  mov r11, qword ptr [rsp+r9*8]\n" + _mba_add("r11", "rcx", key) + _mba_add("rax", "rcx", key)
    ), 9


def _lea_store_asm(width: int, advance: int) -> str:
    """The store-address-into-slot tail shared by the lea handlers.

    A 32-bit destination truncates the address to its low 32 bits, zero-extended
    into the 64-bit slot (``mov r10d, r10d`` clears the upper half); a 64-bit
    destination stores the full address.
    """
    truncate = "  mov r10d, r10d\n" if width == 32 else ""
    return f"{truncate}  mov qword ptr [rsp+r8*8], r10\n  add rsi, {advance}\n  jmp vm_dispatch\n"


def _lea_indexed_handler_asm(handler_key: str, key: int, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for ``lea reg, [base + index*scale + disp]`` (32- or 64-bit dst).

    The effective address is computed with the shared indexed prologue and
    stored into the destination slot without dereferencing; lea sets no flags.
    """
    width = int(handler_key.split("_")[1])
    body, advance = _indexed_address_asm(key, key_dword, field_perm)
    return body + _lea_store_asm(width, advance)


def _lea_indexed_nobase_handler_asm(handler_key: str, key: int, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for ``lea reg, [index*scale + disp]`` (no base, 32- or 64-bit dst).

    Like the indexed prologue but without the base add: the address is
    ``index*scale + disp``. The item has no base-slot byte, so it is one byte
    shorter (size 8). Operand fields are read at this build's permuted offsets.
    lea sets no flags; a 32-bit destination truncates.
    """
    width = int(handler_key.split("_")[1])
    off = idx_offsets(True, field_perm)
    body = (
        f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r11d, byte ptr [rsi+{off['index']}]\n  xor r11b, {key}\n  xor r11b, r13b\n"
        f"  movzx ecx, byte ptr [rsi+{off['shift']}]\n  xor cl, {key}\n  xor cl, r13b\n"
        f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r10d, {key_dword}\n  xor eax, r10d\n"
        + _unmask_dword("r10")
        + "  movsxd rax, eax\n  mov r10, qword ptr [rsp+r11*8]\n  shl r10, cl\n"
        + _mba_add_r10_rax(key)
    )
    return body + _lea_store_asm(width, 8)


def _op_mem_synth_tail(mnemonic: str, width: int, key: int, advance: int) -> str:
    """Tail shared by ``<op> reg, [mem]`` handlers: with the effective address in
    r10 and the register slot index in r8, compute ``reg <op> [mem]`` with the MBA
    fold, synthesize the flags, store the result to the register slot.

    The register operand is a, the loaded memory operand is b; nothing here spells
    out a literal native op or a pushfq.
    """
    if width == 64:
        body = "  mov rbx, qword ptr [rsp+r8*8]\n  mov rax, qword ptr [r10]\n"
    else:
        body = "  mov ebx, dword ptr [rsp+r8*8]\n  mov eax, dword ptr [r10]\n"
    body += "  mov rbp, rax\n"
    if mnemonic == "sub":
        body += "  neg rax\n"
    body += "  mov r10, rbx\n"
    body += _op_mba_compute(mnemonic, key)
    if width == 32:
        body += "  mov r10d, r10d\n"
    body += _synth_flags_asm(width, mnemonic if mnemonic in ("add", "sub") else "logic")
    body += f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    body += "  mov qword ptr [rsp+r8*8], r10\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _op_mem_indexed_handler_asm(handler_key: str, key: int, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for ``<op> reg, [base + index*scale + disp]`` (reg is source
    and destination; memory is the scaled-index source).

    The address is computed with the shared indexed prologue; the result is the
    register combined with memory via the MBA fold and the flags are synthesized.
    """
    _, mnemonic, width_text = handler_key.split("_")
    body, advance = _indexed_address_asm(key, key_dword, field_perm)
    return body + _op_mem_synth_tail(mnemonic, int(width_text), key, advance)


def _lea_handler_asm(handler_key: str, key: int, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for ``lea reg, [base+disp]`` / ``lea reg, [rip+disp]``.

    The effective address is computed exactly like a memory handler, but it is
    stored into the destination slot instead of being dereferenced; lea sets no
    flags. A 32-bit destination truncates the address to its low 32 bits.
    """
    sub, width_text = handler_key.split("_")
    body, advance = _mem_address_asm(sub == "learip", key, key_dword, field_perm)
    return body + _lea_store_asm(int(width_text), advance)


def _op_memory_handler_asm(handler_key: str, key: int, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for ``<op> reg, [mem]`` (reg is source and destination).

    The address is computed like the compare-with-memory handler; the result is the
    register combined with memory via the MBA fold (a 32-bit op zero-extends) and the
    flags are synthesized.
    """
    parts = handler_key.split("_")
    riprel = parts[0] == "opriprel"
    mnemonic, width = parts[1], int(parts[2])
    body, advance = _mem_address_asm(riprel, key, key_dword, field_perm)
    return body + _op_mem_synth_tail(mnemonic, width, key, advance)


def _compare_handler_asm(handler_key: str, key: int, key_qword: str, key_dword: str, field_perm: int = 0) -> str:
    """Assembly body for a cmp/test handler (synthesizes flags, stores no result).

    cmp/test exist only to set flags a branch reads, so both compute the comparison
    with the MBA fold (cmp == ``a - b``, test == ``a & b``; no literal cmp/test) and
    synthesize the readable flags by hand (no pushfq of a literal op). The original
    operands are saved in rbx/rbp before the MBA so the synthesis can read a, b and
    the result; nothing is written back to a register slot.
    """
    mnemonic, mode, width_text = handler_key.split("_")
    width = int(width_text)
    is_immediate = mode == "i"
    # cmp/test carry the same operand fields as an arithmetic op (a slot plus an
    # immediate or a second slot), so they share the arith layout.
    off = op_offsets(is_immediate, width, field_perm)
    body = f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
    if is_immediate and width == 64:
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
        body += "  mov rax, qword ptr [rsp+r9*8]\n" if width == 64 else "  mov eax, dword ptr [rsp+r9*8]\n"
        advance = 3
    # Save the original operands (b before any negation, a before the MBA).
    body += "  mov rbp, rax\n"
    body += "  mov r10, qword ptr [rsp+r8*8]\n" if width == 64 else "  mov r10d, dword ptr [rsp+r8*8]\n"
    body += "  mov rbx, r10\n"
    if mnemonic == "cmp":
        body += "  neg rax\n" + _op_mba_compute("add", key)  # r10 = a - b
        synth_mode = "sub"
    else:
        body += _op_mba_compute("and", key)  # r10 = a & b
        synth_mode = "logic"
    if width == 32:
        body += "  mov r10d, r10d\n"
    body += _synth_flags_asm(width, synth_mode)
    body += f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _shift_handler_asm(handler_key: str, key: int, field_perm: int = 0) -> str:
    """Assembly body for a shl/shr/sar handler (count is an immediate in cl)."""
    mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    off = shift_offsets(field_perm)
    body = (
        f"  movzx r8d, byte ptr [rsi+{off['slot']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx ecx, byte ptr [rsi+{off['count']}]\n  xor cl, {key}\n  xor cl, r13b\n"
    )
    if width == 64:
        body += f"  mov rax, qword ptr [rsp+r8*8]\n  {mnemonic} rax, cl\n"
    else:
        body += f"  mov eax, dword ptr [rsp+r8*8]\n  {mnemonic} eax, cl\n"
    return (
        body
        + f"  mov qword ptr [rsp+r8*8], rax\n  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _imul_handler_asm(handler_key: str, key: int, field_perm: int = 0) -> str:
    """Assembly body for a two-operand register imul handler."""
    width = int(handler_key.split("_")[1])
    # Two register slots - the same field shape as a register-form arithmetic op.
    off = op_offsets(False, width, field_perm)
    body = (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
    )
    if width == 64:
        body += "  mov rax, qword ptr [rsp+r8*8]\n  imul rax, qword ptr [rsp+r9*8]\n"
    else:
        body += "  mov eax, dword ptr [rsp+r8*8]\n  imul eax, dword ptr [rsp+r9*8]\n"
    return (
        body
        + f"  mov qword ptr [rsp+r8*8], rax\n  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _push_handler_asm(key: int, rsp_off: int) -> str:
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


def _pop_handler_asm(key: int, rsp_off: int) -> str:
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
        f"  {mnemonic} qword ptr [rsp+{rsp_off}], rax\n"
        f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
        "  add rsi, 5\n  jmp vm_dispatch\n"
    )


def _mov_from_rsp_handler_asm(key: int, rsp_off: int) -> str:
    """Assembly body for ``mov reg, rsp`` (copy the relocated rsp into a slot)."""
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  mov rax, qword ptr [rsp+{rsp_off}]\n"
        "  mov qword ptr [rsp+r8*8], rax\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _mov_to_rsp_handler_asm(key: int, rsp_off: int) -> str:
    """Assembly body for ``mov rsp, reg`` (restore the relocated rsp from a slot)."""
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        "  mov rax, qword ptr [rsp+r8*8]\n"
        f"  mov qword ptr [rsp+{rsp_off}], rax\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _leave_handler_asm(key: int, rsp_off: int) -> str:
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


def _imul3_handler_asm(handler_key: str, key: int, key_dword: str, field_perm: int = 0) -> str:
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
    if width == 64:
        body += "  movsxd r10, eax\n  mov rax, qword ptr [rsp+r9*8]\n  imul rax, r10\n"
    else:
        body += "  mov r10d, dword ptr [rsp+r9*8]\n  imul r10d, eax\n  mov rax, r10\n"
    return (
        body
        + f"  mov qword ptr [rsp+r8*8], rax\n  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, 7\n  jmp vm_dispatch\n"
    )
