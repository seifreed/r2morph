"""ARM64-specific helpers for instruction substitution."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

logger = logging.getLogger(__name__)

_ARM_MOV_OPERAND_COUNT = 2
_MAX_ARM_MOV_IMMEDIATE = 0xFFFF


def _movz_replacement(disasm: str) -> str | None:
    normalized = disasm.lower().replace("#", "")
    if not normalized.startswith("mov "):
        return None

    parts = [part.strip() for part in normalized.split(",")]
    if len(parts) != _ARM_MOV_OPERAND_COUNT:
        return None

    dst = parts[0].split()[-1]
    immediate = parts[1]
    if not dst.startswith(("w", "x")) or not (immediate.startswith("0x") or immediate.isdigit()):
        return None

    try:
        value = int(immediate, 16) if immediate.startswith("0x") else int(immediate)
    except ValueError:
        return None
    if not 0 <= value <= _MAX_ARM_MOV_IMMEDIATE:
        return None
    return f"movz {dst}, {hex(value)}"


def apply_arm64_mov_substitution(binary: Any, max_substitutions: int) -> dict[str, Any]:
    """Apply safe ARM64 mov-immediate substitutions."""
    functions = binary.get_functions()
    mutations_applied = 0
    functions_mutated = 0

    for func in functions:
        if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
            continue

        try:
            func_addr = func.get("offset", func.get("addr", 0))
            instructions = binary.get_function_disasm(func_addr)
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
            logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
            continue

        func_mutations = 0
        for insn in instructions:
            addr = insn.get("addr", 0)
            size = insn.get("size", 0)
            new_insn = _movz_replacement(insn.get("disasm", ""))
            if new_insn is None:
                continue
            new_bytes = binary.assemble(new_insn, func_addr)

            if not new_bytes or len(new_bytes) != size:
                continue

            if binary.write_bytes(addr, new_bytes):
                func_mutations += 1
                mutations_applied += 1

                if func_mutations >= max_substitutions:
                    break

        if func_mutations > 0:
            functions_mutated += 1

    return {
        "mutations_applied": mutations_applied,
        "functions_mutated": functions_mutated,
        "total_functions": len(functions),
    }


__all__ = ["apply_arm64_mov_substitution"]
