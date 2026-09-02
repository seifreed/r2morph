"""
Code virtualization engine - real, semantics-preserving register VM.

Transforms a straight-line run of general-purpose register instructions
into bytecode for a small stack-context virtual machine. The native run is
replaced by a trampoline into a generated interpreter that spills the
architectural registers to a private stack frame, executes the bytecode
against that context, reloads the registers, and jumps back to the
instruction following the run.

Correctness contract (why this preserves semantics):

- Only GP-register data/arithmetic ops are virtualized
  (``mov``/``add``/``sub``/``xor``/``and``/``or`` with register or
  immediate operands). Both 64-bit and 32-bit operand widths are modeled;
  32-bit handlers reproduce x86-64 zero-extension (the upper half of the
  destination is cleared). A register-to-register op whose operands disagree
  on width is rejected, not approximated.
- ``rsp`` is never an operand: the interpreter owns the stack pointer
  (restores it verbatim on exit), so a run that modified ``rsp`` could
  not be reproduced and is rejected.
- The interpreter clobbers flags, so a run is only virtualized when the
  caller has proven flags are dead after it.
- Memory, RIP-relative, segment, and control-flow operands are modeled only for
  the supported general-purpose transfer forms; unsupported forms end the run.

A run that cannot be proven correct yields ``None`` - the caller leaves
the function untouched. Zero virtualizations always beats a corrupt one.
"""

from __future__ import annotations

import r2morph.core.randomness as random
from r2morph.mutations.code_virtualization_engine_build import build_vm_blob
from r2morph.mutations.code_virtualization_engine_codegen import (
    _interpreter_asm,
    encode_bytecode,
)
from r2morph.mutations.code_virtualization_engine_common import (
    _OPAQUE_VARIANTS,
    _SHIFT_KINDS,
    GP_REGISTERS,
    REGISTER32_INDEX,
    REGISTER_INDEX,
    RSP_INDEX,
    SUPPORTED_MNEMONICS,
    VMScheme,
    _opaque_predicate_asm,
    build_vm_scheme,
    gp_save_order,
    immediate_fits_width,
    pack_immediate,
)
from r2morph.mutations.code_virtualization_engine_models import (
    VirtualizedFpArithMemOp,
    VirtualizedFpArithOp,
    VirtualizedFpConvertOp,
    VirtualizedFpMemOp,
    VirtualizedFpPackedImmediateOp,
    VirtualizedFpPackedMemOp,
    VirtualizedFpPackedOp,
    VirtualizedFpScalarVexOp,
    VirtualizedMemOp,
    VirtualizedOp,
)

# Mean junk ops inserted per real op. ``mov reg, reg`` is a perfect identity (a
# slot written with its own value, no flags), so it is semantics-preserving for
# any register, yet it executes a real handler and pads the bytecode with
# operations a devirtualizer cannot distinguish from the program's. The run is
# straight-line (no branches), so insertion needs no target remap. Kept modest so
# the per-run execution cost stays bounded. Mirrors the region lifter's tuning.
_JUNK_OP_PROBABILITY = 0.35
_INSTRUCTION_PART_COUNT = 2


def inject_junk_ops(
    ops: list[
        VirtualizedOp
        | VirtualizedMemOp
        | VirtualizedFpMemOp
        | VirtualizedFpArithOp
        | VirtualizedFpConvertOp
        | VirtualizedFpArithMemOp
        | VirtualizedFpPackedOp
        | VirtualizedFpPackedImmediateOp
        | VirtualizedFpPackedMemOp
        | VirtualizedFpScalarVexOp
    ],
    rng: random.Random,
) -> list[
    VirtualizedOp
    | VirtualizedMemOp
    | VirtualizedFpMemOp
    | VirtualizedFpArithOp
    | VirtualizedFpConvertOp
    | VirtualizedFpArithMemOp
    | VirtualizedFpPackedOp
    | VirtualizedFpPackedImmediateOp
    | VirtualizedFpPackedMemOp
    | VirtualizedFpScalarVexOp
]:
    """Sprinkle identity ``mov reg, reg`` ops through a straight-line run."""
    junk_regs = [index for index in range(len(GP_REGISTERS)) if index != RSP_INDEX]
    out: list[
        VirtualizedOp
        | VirtualizedMemOp
        | VirtualizedFpMemOp
        | VirtualizedFpArithOp
        | VirtualizedFpConvertOp
        | VirtualizedFpArithMemOp
        | VirtualizedFpPackedOp
        | VirtualizedFpPackedImmediateOp
        | VirtualizedFpPackedMemOp
        | VirtualizedFpScalarVexOp
    ] = []
    for op in ops:
        while rng.random() < _JUNK_OP_PROBABILITY:
            reg = rng.choice(junk_regs)
            out.append(VirtualizedOp("mov", reg, reg, False, 64))
        out.append(op)
    return out


def _normalize_operand(token: str) -> str:
    return token.strip().lower()


def _parse_immediate(token: str) -> int | None:
    token = token.strip()
    try:
        return int(token, 0)
    except ValueError:
        return None


def _register_slot(name: str) -> tuple[int, int] | None:
    """Return (slot, width) for a 64- or 32-bit GP register, else None.

    The stack pointer is excluded in both widths: the interpreter owns rsp.
    """
    if name in REGISTER_INDEX:
        return (REGISTER_INDEX[name], 64) if name != "rsp" else None
    if name in REGISTER32_INDEX:
        return (REGISTER32_INDEX[name], 32) if name != "esp" else None
    return None


def _decode_source(mnemonic: str, dst_slot: int, width: int, source: str) -> VirtualizedOp | None:
    source_slot = _register_slot(source)
    if source_slot is not None:
        slot, source_width = source_slot
        return VirtualizedOp(mnemonic, dst_slot, slot, False, width) if source_width == width else None
    if any(marker in source for marker in ("[", "]", "rip", ":", "ptr")):
        return None
    immediate = _parse_immediate(source)
    if immediate is None or not immediate_fits_width(immediate, width):
        return None
    return VirtualizedOp(mnemonic, dst_slot, immediate, True, width)


def decode_instruction(disasm: str) -> VirtualizedOp | None:
    """
    Decode one disassembled instruction into a :class:`VirtualizedOp`.

    Returns ``None`` for anything the VM cannot reproduce exactly: a
    non-supported mnemonic, a non-GP register, a memory/RIP/segment operand,
    any stack-pointer involvement, or a register-to-register op whose operands
    disagree on width.
    """
    parts = disasm.strip().split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT:
        return None

    mnemonic, operand_text = parts
    mnemonic = "mov" if mnemonic.lower() == "movabs" else mnemonic.lower()
    # ``movabs`` is the disassembler's spelling of a ``mov`` with a 64-bit
    # immediate (or an absolute moffs, which the memory-operand guard below
    # rejects); treat it as a plain ``mov`` so 64-bit constants virtualize.
    if mnemonic not in SUPPORTED_MNEMONICS or "," not in operand_text:
        return None
    dst_token, src_token = operand_text.split(",", 1)
    dst = _register_slot(_normalize_operand(dst_token))
    src_name = _normalize_operand(src_token)
    if dst is None:
        return None
    dst_slot, width = dst

    return _decode_source(mnemonic, dst_slot, width, src_name)


__all__ = [
    "GP_REGISTERS",
    "REGISTER32_INDEX",
    "REGISTER_INDEX",
    "RSP_INDEX",
    "SUPPORTED_MNEMONICS",
    "_OPAQUE_VARIANTS",
    "_SHIFT_KINDS",
    "VMScheme",
    "VirtualizedFpArithMemOp",
    "VirtualizedFpArithOp",
    "VirtualizedFpConvertOp",
    "VirtualizedFpMemOp",
    "VirtualizedFpPackedImmediateOp",
    "VirtualizedFpPackedMemOp",
    "VirtualizedFpPackedOp",
    "VirtualizedFpScalarVexOp",
    "VirtualizedMemOp",
    "VirtualizedOp",
    "_interpreter_asm",
    "_opaque_predicate_asm",
    "build_vm_blob",
    "build_vm_scheme",
    "decode_instruction",
    "encode_bytecode",
    "gp_save_order",
    "immediate_fits_width",
    "inject_junk_ops",
    "pack_immediate",
]
