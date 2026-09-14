"""Checks for instruction streams that can be copied without re-encoding."""

from __future__ import annotations

from typing import Any

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
    return True


__all__ = ["instructions_are_relocatable"]
