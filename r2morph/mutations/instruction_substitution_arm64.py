"""ARM64-specific helpers for instruction substitution."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

logger = logging.getLogger(__name__)


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
            disasm = insn.get("disasm", "").lower().replace("#", "")
            addr = insn.get("addr", 0)
            size = insn.get("size", 0)

            if not disasm.startswith("mov "):
                continue

            parts = [p.strip() for p in disasm.split(",")]
            if len(parts) != 2:
                continue

            dst = parts[0].split()[-1]
            imm = parts[1]

            if not (dst.startswith("w") or dst.startswith("x")):
                continue

            if not imm.startswith("0x") and not imm.isdigit():
                continue

            try:
                imm_val = int(imm, 16) if imm.startswith("0x") else int(imm)
            except ValueError:
                continue

            if imm_val < 0 or imm_val > 0xFFFF:
                continue

            new_insn = f"movz {dst}, {hex(imm_val)}"
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
