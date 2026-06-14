"""Pure parsing helpers for switch-table analysis."""

from __future__ import annotations

import re
from typing import Any

from r2morph.analysis.switch_table_models import IndirectJump
from r2morph.analysis.switch_table_patterns import JUMP_TABLE_PATTERNS, PLT_PATTERNS, TAIL_CALL_PATTERNS


def match_jumptable_operands(disasm: str) -> dict[str, Any] | None:
    """Match a jump-table addressing pattern and extract its operands."""
    for pattern, ptype in JUMP_TABLE_PATTERNS:
        match = re.search(pattern, disasm, re.IGNORECASE)
        if not match:
            continue

        groups = match.groups()
        base_register = None
        index_register = None
        scale = 1
        displacement = 0

        if ptype == "indexed_scaled_offset" and len(groups) >= 3:
            index_register = groups[0]
            scale = int(groups[1])
            displacement = int(groups[2], 16)
        elif ptype == "indexed_scaled" and len(groups) >= 2:
            index_register = groups[0]
            scale = int(groups[1])
        elif ptype == "indexed_offset" and len(groups) >= 2:
            base_register = groups[0]
            displacement = int(groups[1], 16)
        elif ptype == "indexed":
            base_register = groups[0] if groups[0] else None
            index_register = groups[0] if not base_register else None

        return {
            "base_register": base_register,
            "index_register": index_register,
            "scale": scale,
            "displacement": displacement,
            "table_address": displacement if (base_register and displacement) else None,
        }

    return None


def classify_indirect_jump(address: int, disasm: str, function_address: int) -> IndirectJump | None:
    """Classify an indirect jump instruction."""
    operands = match_jumptable_operands(disasm)
    if operands is not None:
        jump_type = "jumptable"
    else:
        jump_type = "unknown"
        operands = {
            "base_register": None,
            "index_register": None,
            "scale": 1,
            "displacement": 0,
            "table_address": None,
        }
    base_register = operands["base_register"]
    index_register = operands["index_register"]
    scale = operands["scale"]
    displacement = operands["displacement"]
    table_address = operands["table_address"]

    if jump_type == "unknown":
        for pattern, ptype in TAIL_CALL_PATTERNS:
            match = re.search(pattern, disasm, re.IGNORECASE)
            if match:
                jump_type = "tailcall"
                groups = match.groups()
                if ptype == "absolute":
                    target = int(groups[0], 16)
                    return IndirectJump(
                        address=address,
                        instruction=disasm,
                        jump_type=jump_type,
                        target_candidates=[target],
                        function_address=function_address,
                    )
                break

    for pattern in PLT_PATTERNS:
        if re.search(pattern, disasm, re.IGNORECASE):
            jump_type = "plt"
            break

    if jump_type == "unknown" and ("[" in disasm or "rip" in disasm):
        jump_type = "indirect"

    if jump_type == "unknown":
        return None

    return IndirectJump(
        address=address,
        instruction=disasm,
        jump_type=jump_type,
        base_register=base_register,
        index_register=index_register,
        scale=scale,
        displacement=displacement,
        table_address=table_address,
        function_address=function_address,
    )
