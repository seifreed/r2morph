"""Assembly bodies for the region VM's scalar and packed FP (SSE) handlers.

Split out of :mod:`code_virtualization_region_handlers` (which keeps the GP and
memory handlers) to keep each file within the module-size budget. These render
the native assembly for one FP handler instance the same way the GP handlers do -
decrypt operands, run the real SSE op, route xmm state through the frame's save
area - and reuse the GP module's shared address prologues and frame offsets.
"""

from __future__ import annotations

from dataclasses import dataclass

from r2morph.mutations.code_virtualization_layout import pair_offsets, triple_offsets
from r2morph.mutations.code_virtualization_region_handlers import (
    _DWORD_WIDTH_BITS,
    _FLAGS_OFFSET,
    _QWORD_WIDTH_BITS,
    _XMM_SAVE_OFFSET,
)
from r2morph.mutations.code_virtualization_region_memory_handlers import (
    _indexed_address_asm,
    _indexed_address_nobase_asm,
    _mem_address_asm,
)


def xmm_spill_asm() -> str:
    """Spill all 16 XMM registers into their frame slots (movups: no alignment
    requirement, so it is correct whatever rsp's 16-alignment happens to be)."""
    return "".join(f"  movups [rsp + {_XMM_SAVE_OFFSET + i * 16}], xmm{i}\n" for i in range(16))


def xmm_reload_asm() -> str:
    """Reload all 16 XMM registers from their frame slots before leaving the VM."""
    return "".join(f"  movups xmm{i}, [rsp + {_XMM_SAVE_OFFSET + i * 16}]\n" for i in range(16))


def avx128_upper_clear_asm(destinations: set[int]) -> str:
    """Clear the YMM upper half for VEX.128 destinations after XMM reload."""
    return "".join(
        f"  vpxor ymm{index}, ymm{index}, ymm{index}\n"
        f"  movups xmm{index}, [rsp + {_XMM_SAVE_OFFSET + index * 16}]\n"
        for index in sorted(destinations)
    )


_YMM_UPPER_SAVE_OFFSET = 0x300


@dataclass(frozen=True)
class VexMemoryHandlerConfig:
    field_perm: int = 0
    addr_variant: int = 0
    preserve_ymm: bool = False


def ymm_upper_spill_asm() -> str:
    """Spill the upper 128 bits needed to preserve live YMM state."""
    return "".join(
        f"  vextractf128 xmm0, ymm{index}, 1\n" f"  movups [rsp + {_YMM_UPPER_SAVE_OFFSET + index * 16}], xmm0\n"
        for index in range(16)
    )


def ymm_upper_reload_asm() -> str:
    """Restore the upper 128 bits after the lower XMM slots are reloaded."""
    return "".join(
        f"  vinsertf128 ymm{index}, ymm{index}, xmmword ptr [rsp + {_YMM_UPPER_SAVE_OFFSET + index * 16}], 1\n"
        for index in range(16)
    )


def vzeroupper_handler_asm() -> str:
    """Clear all saved YMM upper halves while preserving saved XMM values."""
    clear = "  pxor xmm0, xmm0\n"
    clear += "".join(f"  movups [rsp + {_YMM_UPPER_SAVE_OFFSET + index * 16}], xmm0\n" for index in range(16))
    return clear + "  add rsi, 1\n  jmp vm_dispatch\n"


def vzeroall_handler_asm() -> str:
    """Clear all saved XMM and YMM upper halves."""
    clear = "  pxor xmm0, xmm0\n"
    clear += "".join(
        f"  movups [rsp + {_XMM_SAVE_OFFSET + index * 16}], xmm0\n"
        f"  movups [rsp + {_YMM_UPPER_SAVE_OFFSET + index * 16}], xmm0\n"
        for index in range(16)
    )
    return clear + "  add rsi, 1\n  jmp vm_dispatch\n"


def _load_ymm_from_frame(offset: str, register: int) -> str:
    return (
        f"  movups xmm{register}, [rsp + {offset} + {_XMM_SAVE_OFFSET}]\n"
        f"  movups xmm2, [rsp + {offset} + {_YMM_UPPER_SAVE_OFFSET}]\n"
        f"  vinsertf128 ymm{register}, ymm{register}, xmm2, 1\n"
    )


def _store_ymm_to_frame(offset: str) -> str:
    return (
        f"  movups [rsp + {offset} + {_XMM_SAVE_OFFSET}], xmm0\n"
        f"  vextractf128 xmm2, ymm0, 1\n"
        f"  movups [rsp + {offset} + {_YMM_UPPER_SAVE_OFFSET}], xmm2\n"
    )


def _clear_ymm_upper_slot_asm(offset: str) -> str:
    """Commit a VEX.128 destination's zeroed YMM upper half to its slot."""
    return f"  pxor xmm2, xmm2\n  movups [rsp + {offset} + {_YMM_UPPER_SAVE_OFFSET}], xmm2\n"


def _fp_packed_vex_256_arith_handler_asm(handler_key: str, key: str, field_perm: int = 0) -> str:
    """Run a VEX.256 packed operation while preserving full YMM state."""
    instruction = handler_key.split("_", 1)[1]
    off = triple_offsets("dst", "src1", "src2", field_perm)
    body = (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src1']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        f"  movzx r10d, byte ptr [rsi+{off['src2']}]\n  xor r10b, {key}\n  xor r10b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n  shl r10, 4\n"
    )
    body += _load_ymm_from_frame("r9", 0)
    body += _load_ymm_from_frame("r10", 1)
    if instruction.startswith("sqrt"):
        body += f"  v{instruction} ymm0, ymm1\n"
    else:
        body += f"  v{instruction} ymm0, ymm0, ymm1\n"
    body += _store_ymm_to_frame("r8")
    return body + "  add rsi, 4\n  jmp vm_dispatch\n"


def _fp_vex_256_move_handler_asm(handler_key: str, key: str, field_perm: int = 0) -> str:
    """Copy a complete VEX.256 register into the destination frame slot."""
    off = pair_offsets("dst", "src", field_perm)
    body = (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n"
    )
    body += _load_ymm_from_frame("r9", 0)
    body += _store_ymm_to_frame("r8")
    return body + "  add rsi, 3\n  jmp vm_dispatch\n"


def _fp_vex_256_memory_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Move a complete VEX.256 value between memory and a YMM frame slot."""
    if handler_key.endswith("idxnb"):
        body, advance = _indexed_address_nobase_asm(key, key_dword, field_perm, addr_variant)
    elif handler_key.endswith("idx"):
        body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    else:
        body, advance = _mem_address_asm(handler_key.endswith("rip"), key, key_dword, field_perm, addr_variant)
    body += "  shl r8, 4\n"
    if handler_key.startswith("fpload"):
        body += "  vmovups ymm0, [r10]\n" + _store_ymm_to_frame("r8")
    else:
        body += _load_ymm_from_frame("r8", 0) + "  vmovups [r10], ymm0\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _fp_vex_256_packed_arith_mem_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Run a VEX.256 packed operation with its third operand in memory."""
    kind, instruction = handler_key.split("_", 1)
    if kind.endswith("idxnb"):
        body, advance = _indexed_address_nobase_asm(key, key_dword, field_perm, addr_variant)
    elif kind.endswith("idx"):
        body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    else:
        body, advance = _mem_address_asm(kind.endswith("rip"), key, key_dword, field_perm, addr_variant)
    body += f"  movzx r11d, byte ptr [rsi+{advance}]\n  xor r11b, {key}\n  xor r11b, r13b\n" "  shl r11, 4\n"
    body += _load_ymm_from_frame("r11", 0)
    body += "  vmovups ymm1, [r10]\n"
    body += (
        f"  v{instruction} ymm0, ymm1\n" if instruction.startswith("sqrt") else f"  v{instruction} ymm0, ymm0, ymm1\n"
    )
    body += "  shl r8, 4\n"
    body += _store_ymm_to_frame("r8")
    return body + f"  add rsi, {advance + 1}\n  jmp vm_dispatch\n"


def _fp_vex_packed_arith_mem_handler_asm(
    handler_key: str,
    key: str,
    key_dword: str,
    config: VexMemoryHandlerConfig | None = None,
) -> str:
    """Run a VEX.128 packed operation with its third operand in memory."""
    config = config or VexMemoryHandlerConfig()
    kind, instruction = handler_key.split("_", 1)
    if kind.endswith("idxnb"):
        body, advance = _indexed_address_nobase_asm(key, key_dword, config.field_perm, config.addr_variant)
    elif kind.endswith("idx"):
        body, advance = _indexed_address_asm(key, key_dword, config.field_perm, config.addr_variant)
    else:
        body, advance = _mem_address_asm(kind.endswith("rip"), key, key_dword, config.field_perm, config.addr_variant)
    body += f"  movzx r11d, byte ptr [rsi+{advance}]\n  xor r11b, {key}\n  xor r11b, r13b\n"
    body += "  shl r8, 4\n  shl r11, 4\n" f"  movups xmm0, [rsp + r11 + {_XMM_SAVE_OFFSET}]\n" "  movups xmm1, [r10]\n"
    body += (
        f"  v{instruction} xmm0, xmm1\n" if instruction.startswith("sqrt") else f"  v{instruction} xmm0, xmm0, xmm1\n"
    )
    clear_upper = _clear_ymm_upper_slot_asm("r8") if config.preserve_ymm else ""
    body += f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n" + clear_upper
    return body + f"  add rsi, {advance + 1}\n  jmp vm_dispatch\n"


def _fp_memory_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Assembly body for a scalar-FP load/store handler (``movsd``/``movss`` xmm
    <-> [base+disp] or [rip+disp]).

    The shared address prologue decrypts the operand fields - here the "register"
    field is the XMM index (0-15), not a GP slot - and computes the effective
    address into r10 (a frame-slot base plus displacement, or the bytecode base
    plus a stored offset for the rip-relative form). The handler moves between
    program memory and the XMM save slot via the real xmm0 (free scratch during VM
    execution, since every program XMM lives in a slot). ``movsd``/``movss`` loads
    zero the high lanes of the destination, matching x86-64, so the full 16-byte
    slot is rewritten. FP moves set no flags, so the captured-flags slot is
    untouched.
    """
    kind, width_text = handler_key.split("_")
    width = int(width_text)
    riprel = kind.endswith("rip")
    is_load = kind.startswith("fpload")
    move = "movsd" if width == _QWORD_WIDTH_BITS else "movss"
    mem = "qword" if width == _QWORD_WIDTH_BITS else "dword"
    body, advance = _mem_address_asm(riprel, key, key_dword, field_perm, addr_variant)
    # r8 holds the XMM index; scale to the 16-byte slot stride (no *16 index scale
    # exists, so shift into r11 and address base+index+disp at scale 1).
    body += "  mov r11, r8\n  shl r11, 4\n"
    if is_load:
        body += f"  {move} xmm0, {mem} ptr [r10]\n  movups [rsp + r11 + {_XMM_SAVE_OFFSET}], xmm0\n"
    else:
        body += f"  movups xmm0, [rsp + r11 + {_XMM_SAVE_OFFSET}]\n  {move} {mem} ptr [r10], xmm0\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _fp_arith_handler_asm(handler_key: str, key: str, field_perm: int = 0) -> str:
    """Assembly body for a scalar-FP register-register arithmetic handler
    (``addsd``/``subsd``/``mulsd``/``divsd``/``sqrtsd``/``minsd``/``maxsd`` and
    their ``ss`` forms).

    The two operand bytes are XMM indices (un-masked with the key and the stream
    position like every operand) read at this build's permuted offsets; both
    registers are loaded from their save slots into the real xmm0/xmm1 (free scratch
    during VM execution), the scalar op runs on the low lane leaving the high lanes
    of the destination untouched, and the result is written back to the
    destination's slot. FP arithmetic sets no flags, so the captured-flags slot is
    untouched.
    """
    _, mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    instr = mnemonic + ("sd" if width == _QWORD_WIDTH_BITS else "ss")
    off = pair_offsets("dst", "src", field_perm)
    return (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n"
        f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  movups xmm1, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n"
        f"  {instr} xmm0, xmm1\n"
        f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
        "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _fp_indexed_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Assembly body for a scalar-FP load/store with scaled-index addressing
    (``movsd/movss xmm, [base+index*scale+disp]`` - array-of-double access), with or
    without a base register.

    The shared scaled-index prologue decrypts the operand fields - here the
    "register" field is the XMM index - and computes the address into r10 (with the
    base for the ``idx`` form, or index*scale+disp for the no-base ``idxnb`` form).
    The move runs through the real xmm0 between program memory and the XMM save
    slot; loads zero the destination's high lanes, matching x86-64. No flags.
    """
    kind, width_text = handler_key.split("_")
    width = int(width_text)
    move = "movsd" if width == _QWORD_WIDTH_BITS else "movss"
    mem = "qword" if width == _QWORD_WIDTH_BITS else "dword"
    if kind.endswith("nb"):
        body, advance = _indexed_address_nobase_asm(key, key_dword, field_perm, addr_variant)
    else:
        body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    # r8 holds the XMM index; scale to the 16-byte slot stride (it is not needed
    # again, so shift it in place).
    body += "  shl r8, 4\n"
    if kind.startswith("fpload"):
        body += f"  {move} xmm0, {mem} ptr [r10]\n  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
    else:
        body += f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  {move} {mem} ptr [r10], xmm0\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _fp_packed_arith_handler_asm(handler_key: str, key: str, field_perm: int = 0) -> str:
    """Assembly body for a packed-FP register-register op (``addpd``/``addps`` and
    the sub/mul/div/sqrt forms), operating on all lanes of the 128-bit register.

    Both operand bytes are XMM indices, read at this build's permuted offsets. The
    operands are loaded whole from their save slots into xmm0/xmm1, the packed op
    runs across all lanes, and the full 128-bit result is written back. No flags,
    and (unlike the scalar forms) no upper-lane preservation - the op defines every
    lane.
    """
    instr = handler_key.split("_", 1)[1]
    off = pair_offsets("dst", "src", field_perm)
    return (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n"
        f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  movups xmm1, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n"
        f"  {instr} xmm0, xmm1\n"
        f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
        "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _fp_packed_shift_immediate_handler_asm(handler_key: str, key: str, field_perm: int = 0) -> str:
    """Apply a legacy packed integer operation with an encrypted immediate byte."""
    _, instruction, immediate_text = handler_key.split("_")
    immediate = int(immediate_text)
    off = pair_offsets("dst", "imm", field_perm)
    return (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        "  shl r8, 4\n"
        f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  {instruction} xmm0, {immediate}\n"
        f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
        "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _fp_vex_packed_shift_immediate_handler_asm(
    handler_key: str, key: str, field_perm: int = 0, preserve_ymm: bool = False
) -> str:
    """Apply a VEX.128 packed integer operation with an immediate byte."""
    _, instruction, immediate_text = handler_key.split("_")
    immediate = int(immediate_text)
    off = pair_offsets("dst", "src", field_perm)
    clear_upper = _clear_ymm_upper_slot_asm("r8") if preserve_ymm else ""
    return (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n"
        f"  movups xmm0, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n  v{instruction} xmm0, xmm0, {immediate}\n"
        f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n" + clear_upper + "  add rsi, 4\n  jmp vm_dispatch\n"
    )


def _fp_vex_256_packed_shift_immediate_handler_asm(handler_key: str, key: str, field_perm: int = 0) -> str:
    """Apply a VEX.256 packed integer operation with an immediate byte."""
    _, instruction, immediate_text = handler_key.split("_")
    immediate = int(immediate_text)
    off = pair_offsets("dst", "src", field_perm)
    return (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n"
        + _load_ymm_from_frame("r9", 0)
        + f"  v{instruction} ymm0, ymm0, {immediate}\n"
        + _store_ymm_to_frame("r8")
        + "  add rsi, 4\n  jmp vm_dispatch\n"
    )


def _fp_packed_vex_arith_handler_asm(
    handler_key: str, key: str, field_perm: int = 0, preserve_ymm: bool = False
) -> str:
    """Run a VEX.128 packed operation while preserving unrelated YMM upper halves."""
    instr = handler_key.split("_", 1)[1]
    off = triple_offsets("dst", "src1", "src2", field_perm)
    clear_upper = _clear_ymm_upper_slot_asm("r8") if preserve_ymm else ""
    return (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src1']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        f"  movzx r10d, byte ptr [rsi+{off['src2']}]\n  xor r10b, {key}\n  xor r10b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n  shl r10, 4\n"
        f"  movups xmm0, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n"
        f"  movups xmm1, [rsp + r10 + {_XMM_SAVE_OFFSET}]\n"
        f"  {instr} xmm0, xmm1\n"
        f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n" + clear_upper + "  add rsi, 4\n  jmp vm_dispatch\n"
    )


def _fp_vex_scalar_arith_handler_asm(
    handler_key: str, key: str, field_perm: int = 0, preserve_ymm: bool = False
) -> str:
    """Run VEX.128 scalar arithmetic with src1 upper-lane semantics."""
    _, operation, width_text = handler_key.split("_")
    width = int(width_text)
    suffix = "ss" if width == _DWORD_WIDTH_BITS else "sd"
    off = triple_offsets("dst", "src1", "src2", field_perm)
    clear_upper = _clear_ymm_upper_slot_asm("r8") if preserve_ymm else ""
    operation_asm = (
        f"  sqrt{suffix} xmm1, xmm1\n  mov{suffix} xmm0, xmm1\n"
        if operation == "sqrt"
        else f"  v{operation}{suffix} xmm0, xmm0, xmm1\n"
    )
    return (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src1']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        f"  movzx r10d, byte ptr [rsi+{off['src2']}]\n  xor r10b, {key}\n  xor r10b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n  shl r10, 4\n"
        f"  movups xmm0, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n"
        f"  movups xmm1, [rsp + r10 + {_XMM_SAVE_OFFSET}]\n"
        + operation_asm
        + f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
        + clear_upper
        + "  add rsi, 4\n  jmp vm_dispatch\n"
    )


def _fp_vex_scalar_move_handler_asm(handler_key: str, key: str, field_perm: int = 0, preserve_ymm: bool = False) -> str:
    """Run a two-operand VEX scalar move, which clears unused XMM lanes."""
    _, width_text = handler_key.split("_")
    suffix = "ss" if int(width_text) == _DWORD_WIDTH_BITS else "sd"
    off = pair_offsets("dst", "src", field_perm)
    clear_upper = _clear_ymm_upper_slot_asm("r8") if preserve_ymm else ""
    return (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n"
        f"  movups xmm0, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n"
        f"  vmov{suffix} xmm0, xmm0\n"
        f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n" + clear_upper + "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _fp_vex_scalar_merge_handler_asm(
    handler_key: str, key: str, field_perm: int = 0, preserve_ymm: bool = False
) -> str:
    """Run a three-operand VEX scalar move with a non-destructive source."""
    _, width_text = handler_key.split("_")
    suffix = "ss" if int(width_text) == _DWORD_WIDTH_BITS else "sd"
    off = triple_offsets("dst", "src1", "src2", field_perm)
    clear_upper = _clear_ymm_upper_slot_asm("r8") if preserve_ymm else ""
    return (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src1']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        f"  movzx r10d, byte ptr [rsi+{off['src2']}]\n  xor r10b, {key}\n  xor r10b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n  shl r10, 4\n"
        f"  movups xmm0, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n"
        f"  movups xmm1, [rsp + r10 + {_XMM_SAVE_OFFSET}]\n"
        f"  vmov{suffix} xmm0, xmm0, xmm1\n"
        f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n" + clear_upper + "  add rsi, 4\n  jmp vm_dispatch\n"
    )


def _fp_vex_gp_move_handler_asm(handler_key: str, key: str, field_perm: int = 0, preserve_ymm: bool = False) -> str:
    """Transfer a qword between a GP frame slot and an XMM frame slot."""
    _, direction = handler_key.split("_", 1)
    off = pair_offsets("xmm", "gp", field_perm)
    decode = (
        f"  movzx r8d, byte ptr [rsi+{off['xmm']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['gp']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
    )
    if direction == "gp_to_xmm":
        clear_upper = _clear_ymm_upper_slot_asm("r8") if preserve_ymm else ""
        return decode + (
            "  mov rax, qword ptr [rsp + r9*8]\n  vmovq xmm0, rax\n"
            f"  shl r8, 4\n  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
            + clear_upper
            + "  add rsi, 3\n  jmp vm_dispatch\n"
        )
    return decode + (
        f"  shl r8, 4\n  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n"
        "  vmovq rax, xmm0\n  mov qword ptr [rsp + r9*8], rax\n"
        "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _fp_vex_scalar_memory_move_handler_asm(
    handler_key: str,
    key: str,
    key_dword: str,
    config: VexMemoryHandlerConfig | None = None,
) -> str:
    """Run a VEX scalar load/store or merge-load memory form."""
    config = config or VexMemoryHandlerConfig()
    kind, width_text = handler_key.rsplit("_", 1)
    suffix = "ss" if int(width_text) == _DWORD_WIDTH_BITS else "sd"
    memory = "dword" if suffix == "ss" else "qword"
    if kind.endswith("idxnb"):
        body, advance = _indexed_address_nobase_asm(key, key_dword, config.field_perm, config.addr_variant)
    elif kind.endswith("idx"):
        body, advance = _indexed_address_asm(key, key_dword, config.field_perm, config.addr_variant)
    else:
        body, advance = _mem_address_asm(kind.endswith("rip"), key, key_dword, config.field_perm, config.addr_variant)
    body += "  shl r8, 4\n"
    if kind.startswith("fpmovvexmem"):
        body += f"  movzx r11d, byte ptr [rsi+{advance}]\n  xor r11b, {key}\n  xor r11b, r13b\n  shl r11, 4\n"
        body += f"  movups xmm0, [rsp + r11 + {_XMM_SAVE_OFFSET}]\n"
        body += f"  vmov{suffix} xmm0, xmm0, {memory} ptr [r10]\n"
        body += f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
        clear_upper = _clear_ymm_upper_slot_asm("r8") if config.preserve_ymm else ""
        return body + clear_upper + f"  add rsi, {advance + 1}\n  jmp vm_dispatch\n"
    if kind.startswith("fploadvex"):
        body += f"  vmov{suffix} xmm0, {memory} ptr [r10]\n  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
        clear_upper = _clear_ymm_upper_slot_asm("r8") if config.preserve_ymm else ""
        body += clear_upper
    else:
        body += f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  vmov{suffix} {memory} ptr [r10], xmm0\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _fp_vex_scalar_arith_mem_handler_asm(
    handler_key: str,
    key: str,
    key_dword: str,
    config: VexMemoryHandlerConfig | None = None,
) -> str:
    """Run VEX scalar arithmetic with its scalar third operand in memory."""
    config = config or VexMemoryHandlerConfig()
    kind, operation, width_text = handler_key.split("_")
    width = int(width_text)
    suffix = "ss" if width == _DWORD_WIDTH_BITS else "sd"
    memory = "dword" if width == _DWORD_WIDTH_BITS else "qword"
    if kind.endswith("idxnb"):
        body, advance = _indexed_address_nobase_asm(key, key_dword, config.field_perm, config.addr_variant)
    elif kind.endswith("idx"):
        body, advance = _indexed_address_asm(key, key_dword, config.field_perm, config.addr_variant)
    else:
        body, advance = _mem_address_asm(kind.endswith("rip"), key, key_dword, config.field_perm, config.addr_variant)
    body += f"  movzx r11d, byte ptr [rsi+{advance}]\n  xor r11b, {key}\n  xor r11b, r13b\n"
    body += "  shl r8, 4\n  shl r11, 4\n"
    body += f"  movups xmm0, [rsp + r11 + {_XMM_SAVE_OFFSET}]\n"
    if operation == "sqrt":
        body += f"  sqrt{suffix} xmm1, {memory} ptr [r10]\n  mov{suffix} xmm0, xmm1\n"
    else:
        body += f"  v{operation}{suffix} xmm0, xmm0, {memory} ptr [r10]\n"
    body += f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
    clear_upper = _clear_ymm_upper_slot_asm("r8") if config.preserve_ymm else ""
    return body + clear_upper + f"  add rsi, {advance + 1}\n  jmp vm_dispatch\n"


def _fp_vex_move_handler_asm(handler_key: str, key: str, field_perm: int = 0, preserve_ymm: bool = False) -> str:
    """Copy the lower 128 bits of a VEX.128 move into the destination slot."""
    off = pair_offsets("dst", "src", field_perm)
    clear_upper = _clear_ymm_upper_slot_asm("r8") if preserve_ymm else ""
    return (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n"
        f"  movups xmm0, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n"
        f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n" + clear_upper + "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _fp_packed_arith_mem_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Assembly body for packed-FP arithmetic with a ``[base+disp]`` memory source
    (``addpd xmm, [base+disp]`` and the sub/mul/div forms).

    The shared address prologue computes the operand address into r10 (a frame-slot
    base plus displacement, the bytecode base plus a stored offset for the
    rip-relative constant-vector form, or base+index*scale+disp for the array form);
    the destination and the 128-bit memory operand are both loaded with movups (so
    an unaligned operand never faults - a direct packed memory operand would require
    16-byte alignment), the packed op runs across all lanes, and the full result is
    written back. No flags.
    """
    kind, instr = handler_key.split("_", 1)
    if kind.endswith("idxnb"):
        body, advance = _indexed_address_nobase_asm(key, key_dword, field_perm, addr_variant)
    elif kind.endswith("idx"):
        body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    else:
        body, advance = _mem_address_asm(kind.endswith("rip"), key, key_dword, field_perm, addr_variant)
    body += (
        f"  shl r8, 4\n  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n"
        f"  movups xmm1, [r10]\n  {instr} xmm0, xmm1\n"
        f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
    )
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _fp_packed_mem_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Assembly body for a packed 128-bit load/store (``movaps``/``movups`` etc.
    xmm <-> [base+disp], [rip+disp] or [base+index*scale+disp]).

    The shared address prologue computes the address into r10 (a frame-slot base
    plus displacement, the bytecode base plus a stored offset for the rip-relative
    form, or base+index*scale+disp for the scaled-index form); the full 128-bit
    value moves between program memory and the XMM save slot via xmm0. An unaligned
    move (movups) is used throughout: it is correct for aligned data too, and avoids
    any alignment fault from the relocated frame. No flags.
    """
    if handler_key.endswith("idxnb"):
        body, advance = _indexed_address_nobase_asm(key, key_dword, field_perm, addr_variant)
    elif handler_key.endswith("idx"):
        body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    else:
        body, advance = _mem_address_asm(handler_key.endswith("rip"), key, key_dword, field_perm, addr_variant)
    body += "  shl r8, 4\n"
    if handler_key.startswith("fppload"):
        body += f"  movups xmm0, [r10]\n  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
    else:
        body += f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  movups [r10], xmm0\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _fp_arith_mem_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Assembly body for scalar-FP arithmetic with a memory source - either
    ``[base+disp]`` or rip-relative ``[rip+disp]`` (the constant-pool form).

    The shared address prologue decrypts the operand fields - here the "register"
    field is the destination XMM index - and computes the effective address into
    r10: a frame-slot base plus displacement, the bytecode base plus a stored
    offset (rip-relative), or base+index*scale+disp (the accumulation form). The
    destination is loaded from its save slot, the scalar op runs against the memory
    operand on the low lane (upper lanes preserved), and the result is written
    back. FP arithmetic sets no flags.
    """
    kind, mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    instr = mnemonic + ("sd" if width == _QWORD_WIDTH_BITS else "ss")
    mem = "qword" if width == _QWORD_WIDTH_BITS else "dword"
    if kind.endswith("idxnb"):
        body, advance = _indexed_address_nobase_asm(key, key_dword, field_perm, addr_variant)
    elif kind.endswith("idx"):
        body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    else:
        body, advance = _mem_address_asm(kind.endswith("rip"), key, key_dword, field_perm, addr_variant)
    body += f"  shl r8, 4\n  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n"
    body += f"  {instr} xmm0, {mem} ptr [r10]\n  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _fp_convert_handler_asm(handler_key: str, key: str, field_perm: int = 0) -> str:
    """Assembly body for an int<->float conversion handler (``cvtsi2sd/ss``
    int->float, ``cvttsd2si/ss`` float->int, truncating).

    Both operands - an XMM index (r8) and a GP slot (r9) - are un-masked with the
    key and stream position and read at this build's permuted offsets. The GP width
    is part of the key: a 32-bit operand uses eax/dword, a 64-bit one rax/qword - so
    a 32-bit ``cvtsi2sd`` converts the int32 (not the full slot), and a 32-bit
    ``cvttsd2si`` truncates with the int32 saturation semantics (an out-of-range
    double yields 0x80000000), both matching x86-64. ``cvti2f`` converts into the
    destination XMM's low lane, preserving its upper lane (loaded from the slot,
    since the conversion is scalar); ``cvtf2i`` writes the GP destination slot,
    where the eax form zero-extends into the full 64-bit slot. No flags.
    """
    kind, fp_width_text, gp_width_text = handler_key.split("_")
    fp_width = int(fp_width_text)
    gp_reg = "rax" if gp_width_text == "64" else "eax"
    gp_mem = "qword" if gp_width_text == "64" else "dword"
    off = pair_offsets("xmm", "gp", field_perm)
    decode = (
        f"  movzx r8d, byte ptr [rsi+{off['xmm']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['gp']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        "  shl r8, 4\n"
    )
    if kind == "cvti2f":
        instr = "cvtsi2sd" if fp_width == _QWORD_WIDTH_BITS else "cvtsi2ss"
        return decode + (
            f"  mov {gp_reg}, {gp_mem} ptr [rsp + r9*8]\n"
            f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  {instr} xmm0, {gp_reg}\n"
            f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
            "  add rsi, 3\n  jmp vm_dispatch\n"
        )
    instr = "cvttsd2si" if fp_width == _QWORD_WIDTH_BITS else "cvttss2si"
    # The eax form zeroes the upper 32 bits of rax, so the full qword slot write is
    # the zero-extended result.
    return decode + (
        f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  {instr} {gp_reg}, xmm0\n"
        "  mov qword ptr [rsp + r9*8], rax\n"
        "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _fp_movd_handler_asm(handler_key: str, key: str, field_perm: int = 0) -> str:
    """Assembly body for a GP/XMM ``movd`` or ``movq`` transfer."""
    kind, direction = handler_key.split("_", 1)
    is_qword = kind == "fpmovq"
    gp_register = "rax" if is_qword else "eax"
    gp_width = "qword" if is_qword else "dword"
    move_mnemonic = "movq" if is_qword else "movd"
    off = pair_offsets("xmm", "gp", field_perm)
    decode = (
        f"  movzx r8d, byte ptr [rsi+{off['xmm']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['gp']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
    )
    if direction == "gp_to_xmm":
        return decode + (
            f"  mov {gp_register}, {gp_width} ptr [rsp + r9*8]\n"
            f"  {move_mnemonic} xmm0, {gp_register}\n"
            f"  shl r8, 4\n  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
            "  add rsi, 3\n  jmp vm_dispatch\n"
        )
    return decode + (
        f"  shl r8, 4\n  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n"
        f"  {move_mnemonic} {gp_register}, xmm0\n  mov qword ptr [rsp + r9*8], rax\n"
        "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _fp_compare_handler_asm(handler_key: str, key: str, field_perm: int = 0) -> str:
    """Assembly body for a scalar-FP register-register compare
    (``ucomisd``/``comisd`` and the ``ss`` forms).

    Both operands (read at this build's permuted offsets) are loaded from their XMM
    save slots into the real xmm0/xmm1; the real compare runs (no MBA equivalent
    exists for an FP ordered compare) and its flags - ZF/PF/CF, faithfully including
    the unordered/NaN case - are captured into the frame's flags slot with the same
    pushfq/pop idiom the GP handlers use, so the existing branch handler consumes
    them unchanged.
    """
    instr = handler_key.split("_", 1)[1]
    off = pair_offsets("left", "right", field_perm)
    return (
        f"  movzx r8d, byte ptr [rsi+{off['left']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['right']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n"
        f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  movups xmm1, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n"
        f"  {instr} xmm0, xmm1\n"
        f"  pushfq\n  pop qword ptr [rsp + {_FLAGS_OFFSET}]\n"
        "  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _fp_compare_memory_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Compare an XMM value with a scalar memory value and save flags."""
    parts = handler_key.split("_")
    kind, mnemonic, width_text = parts[0], parts[1], parts[-1]
    width = int(width_text)
    if kind.endswith("idxnb"):
        body, advance = _indexed_address_nobase_asm(key, key_dword, field_perm, addr_variant)
    elif kind.endswith("idx"):
        body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    else:
        body, advance = _mem_address_asm(False, key, key_dword, field_perm, addr_variant)
    memory = "qword" if width == _QWORD_WIDTH_BITS else "dword"
    body += (
        f"  shl r8, 4\n  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n"
        f"  {mnemonic} xmm0, {memory} ptr [r10]\n"
        f"  pushfq\n  pop qword ptr [rsp + {_FLAGS_OFFSET}]\n"
    )
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _fp_move_handler_asm(handler_key: str, key: str, field_perm: int = 0) -> str:
    """Assembly body for a register-register xmm move (full 128-bit copy, scalar
    movsd/movss that preserves the destination's upper lane(s), or movq that
    clears the destination's upper qword).

    Both operand bytes are XMM indices, read at this build's permuted offsets. The
    full copy reads the source slot and writes it whole to the destination slot; the
    scalar copy loads the destination slot first so the real movsd/movss preserves
    its high lanes (unlike the memory load forms, which zero them); movq uses the
    real instruction and therefore clears the high qword. No flags.
    """
    mode = handler_key.split("_", 1)[1]
    off = pair_offsets("dst", "src", field_perm)
    decode = (
        f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        "  shl r8, 4\n  shl r9, 4\n"
    )
    if mode == "full":
        body = f"  movups xmm0, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
    else:
        instr = {"sd": "movsd", "ss": "movss", "q": "movq"}[mode]
        body = (
            f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n  movups xmm1, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n"
            f"  {instr} xmm0, xmm1\n  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
        )
    return decode + body + "  add rsi, 3\n  jmp vm_dispatch\n"
