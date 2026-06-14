"""Leaf helpers for full control-flow flattening generation."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

logger = logging.getLogger(__name__)


def select_candidates(binary: Any, functions: list[dict], min_blocks: int) -> list[dict]:
    """Select candidate functions for full CFF."""
    candidates = []

    for func in functions:
        func_addr = func.get("offset", func.get("addr", 0))
        func_size = func.get("size", 0)
        func_name = func.get("name", "")

        if func_size < MINIMUM_FUNCTION_SIZE:
            continue

        if func_name.startswith("sym.imp.") or func_name.startswith("sub."):
            continue

        try:
            blocks = binary.get_basic_blocks(func_addr)
            if len(blocks) >= min_blocks:
                func["_block_count"] = len(blocks)
                candidates.append(func)
        except Exception:
            continue

    candidates.sort(key=lambda f: f.get("_block_count", 0), reverse=True)
    return candidates


def generate_state_table(dispatcher_blocks: list[Any]) -> dict[int, tuple[int, int | None]]:
    """Generate state transition table."""
    state_table: dict[int, tuple[int, int | None]] = {}

    for db in dispatcher_blocks:
        if db.is_exit:
            state_table[db.state_value] = (-1, None)
        elif len(db.successor_states) == 1:
            state_table[db.state_value] = (db.successor_states[0], None)
        elif len(db.successor_states) == 2:
            state_table[db.state_value] = (
                db.successor_states[0],
                db.successor_states[1],
            )

    return state_table


def generate_dispatcher_code(
    state_table: dict[int, tuple[int, int | None]],
    arch: str,
    bits: int,
) -> list[str] | None:
    """Generate assembly code for the dispatcher."""
    if arch not in ("x86", "x86_64", "arm", "arm64"):
        logger.warning(f"Unsupported architecture for CFF: {arch}")
        return None

    if arch in ("x86", "x86_64"):
        return generate_x86_dispatcher(state_table, bits)
    return generate_arm_dispatcher(state_table, bits)


def generate_x86_dispatcher(
    state_table: dict[int, tuple[int, int | None]],
    bits: int,
) -> list[str]:
    """Generate x86/x86_64 dispatcher code."""
    instructions = []
    reg = "eax" if bits == 32 else "rax"

    state_values = sorted(state_table.keys())
    if not state_values:
        return []

    initial_state = state_values[0]

    instructions.extend(
        [
            f"mov {reg}, {initial_state}",
            "dispatcher_loop:",
        ]
    )

    for state in state_values:
        next_true, next_false = state_table[state]

        instructions.append(f"cmp {reg}, {state}")
        instructions.append("jne .+8")

        if next_false is not None:
            instructions.append(f"mov {reg}, {next_true}")
            instructions.append("jmp dispatcher_loop")
            instructions.append(f"mov {reg}, {next_false}")
            instructions.append("jmp dispatcher_loop")
        else:
            if next_true == -1:
                instructions.append("ret")
            else:
                instructions.append(f"mov {reg}, {next_true}")
                instructions.append("jmp dispatcher_loop")

    instructions.append("dispatcher_end:")
    return instructions


def generate_arm_dispatcher(
    state_table: dict[int, tuple[int, int | None]],
    bits: int,
) -> list[str]:
    """Generate ARM/ARM64 dispatcher code."""
    instructions = []
    reg = "r0" if bits == 32 else "x0"

    state_values = sorted(state_table.keys())
    if not state_values:
        return []

    initial_state = state_values[0]

    instructions.append(f"mov {reg}, #{initial_state}")
    instructions.append("dispatcher_loop:")

    for state in state_values:
        next_true, next_false = state_table[state]

        instructions.append(f"cmp {reg}, #{state}")
        instructions.append("bne .+12")

        if next_false is not None:
            instructions.append(f"mov {reg}, #{next_true}")
            instructions.append("b dispatcher_loop")
            instructions.append(f"mov {reg}, #{next_false}")
            instructions.append("b dispatcher_loop")
        else:
            if next_true == -1:
                instructions.append("bx lr")
            else:
                instructions.append(f"mov {reg}, #{next_true}")
                instructions.append("b dispatcher_loop")

    return instructions


def assemble_dispatcher(binary: Any, instructions: list[str]) -> bytes | None:
    """Assemble dispatcher instructions into bytes."""
    assembled = b""
    failures = []

    for insn in instructions:
        try:
            insn_bytes = binary.assemble(insn)
            if insn_bytes:
                assembled += insn_bytes
            else:
                failures.append(insn)
        except Exception as e:
            failures.append(f"{insn}: {e}")
            logger.debug(f"Failed to assemble '{insn}': {e}")

    if failures:
        logger.warning(
            f"Failed to assemble {len(failures)} dispatcher instructions: {failures[:5]}"
            + ("..." if len(failures) > 5 else "")
        )

    return assembled if assembled else None


__all__ = [
    "assemble_dispatcher",
    "generate_arm_dispatcher",
    "generate_dispatcher_code",
    "generate_state_table",
    "generate_x86_dispatcher",
    "select_candidates",
]
