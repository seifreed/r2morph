"""Checks for instruction streams that can be copied without re-encoding."""

from __future__ import annotations

from typing import Any

import capstone

_NON_RELOCATABLE_TYPES = frozenset(
    {
        "call",
        "cjmp",
        "icall",
        "ijmp",
        "jmp",
        "loop",
        "rcall",
        "rjmp",
        "switch",
        "trap",
        "ucall",
        "ujmp",
    }
)
_NON_RELOCATABLE_MNEMONICS = frozenset({"call", "loop", "syscall", "sysret", "iret", "int"})
_RETURN_MNEMONICS = frozenset({"ret", "retn", "retf", "retq"})


def has_pc_relative_memory_operand(instruction: dict[str, Any]) -> bool | None:
    """Return whether an x86-64 instruction addresses memory through RIP."""
    raw_bytes = instruction.get("bytes")
    address = instruction.get("addr", instruction.get("offset"))
    if not isinstance(raw_bytes, str) or not isinstance(address, int):
        return None
    try:
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        decoded = next(decoder.disasm(bytes.fromhex(raw_bytes), address), None)
    except (capstone.CsError, TypeError, ValueError):
        return None
    if decoded is None:
        return None
    return any(
        operand.type == capstone.x86.X86_OP_MEM and operand.mem.base == capstone.x86.X86_REG_RIP
        for operand in decoded.operands
    )


def has_memory_operand(instruction: dict[str, Any]) -> bool | None:
    """Return whether an x86-64 instruction accesses memory."""
    raw_bytes = instruction.get("bytes")
    address = instruction.get("addr", instruction.get("offset"))
    if not isinstance(raw_bytes, str) or not isinstance(address, int):
        return None
    try:
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        decoded = next(decoder.disasm(bytes.fromhex(raw_bytes), address), None)
    except (capstone.CsError, TypeError, ValueError):
        return None
    if decoded is None:
        return None
    return any(operand.type == capstone.x86.X86_OP_MEM for operand in decoded.operands)


def instructions_are_relocatable(instructions: list[dict[str, Any]]) -> bool:
    """Return whether instructions can be copied without changing addresses."""
    for instruction in instructions:
        instruction_type = str(instruction.get("type", "")).lower()
        if instruction_type in _NON_RELOCATABLE_TYPES:
            return False
        if isinstance(instruction.get("jump"), int) or isinstance(instruction.get("fail"), int):
            return False

        mnemonic = str(instruction.get("disasm", "")).split(maxsplit=1)[0].lower()
        if mnemonic in _RETURN_MNEMONICS:
            continue
        if mnemonic in _NON_RELOCATABLE_MNEMONICS or mnemonic.startswith("j"):
            return False
        if "rip" in str(instruction.get("disasm", "")).lower():
            return False
        if "bytes" in instruction:
            pc_relative = has_pc_relative_memory_operand(instruction)
            if pc_relative is True or pc_relative is None:
                return False
    return True


__all__ = ["has_memory_operand", "has_pc_relative_memory_operand", "instructions_are_relocatable"]
