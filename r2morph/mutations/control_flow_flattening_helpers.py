"""Leaf helpers for control-flow flattening candidate analysis."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

logger = logging.getLogger(__name__)

_X86_CONDITIONAL_JUMPS = frozenset(
    {
        "je",
        "jne",
        "jz",
        "jnz",
        "ja",
        "jae",
        "jb",
        "jbe",
        "jg",
        "jge",
        "jl",
        "jle",
        "jo",
        "jno",
        "js",
        "jns",
        "jp",
        "jnp",
        "jcxz",
        "jecxz",
        "jrcxz",
    }
)

_ARM_CONDITIONAL_BRANCHES = frozenset(
    {
        "beq",
        "bne",
        "bcs",
        "bcc",
        "bmi",
        "bpl",
        "bvs",
        "bvc",
        "bhi",
        "bls",
        "bge",
        "blt",
        "bgt",
        "ble",
        "b.eq",
        "b.ne",
        "b.cs",
        "b.cc",
        "b.mi",
        "b.pl",
        "b.vs",
        "b.vc",
        "b.hi",
        "b.ls",
        "b.ge",
        "b.lt",
        "b.gt",
        "b.le",
        "cbz",
        "cbnz",
    }
)


def select_candidates(binary: Any, functions: list[dict], min_blocks: int) -> list[dict]:
    """Select functions suitable for flattening and sort them by block count."""
    candidates = []

    for func in functions:
        block_count = candidate_block_count(binary, func, min_blocks)
        if block_count is not None:
            func["_block_count"] = block_count
            candidates.append(func)

    candidates.sort(key=lambda f: f.get("_block_count", 0), reverse=True)
    return candidates


def candidate_block_count(binary: Any, func: dict, min_blocks: int) -> int | None:
    """Return the basic-block count if ``func`` is a flattening candidate."""
    if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
        return None

    func_name = func.get("name", "")
    if func_name.startswith("sym.imp.") or func_name.startswith("sub."):
        return None

    func_addr = func.get("offset", func.get("addr", 0))
    try:
        blocks = binary.get_basic_blocks(func_addr)
    except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
        logger.debug(f"Failed to analyze function 0x{func_addr:x}: {e}")
        return None

    if len(blocks) >= min_blocks:
        return len(blocks)
    return None


def is_conditional_jump(mnemonic: str, arch: str) -> bool:
    """Check if an instruction is a conditional jump/branch."""
    mnemonic = mnemonic.lower()

    if arch in ("x86", "x86_64"):
        return mnemonic in _X86_CONDITIONAL_JUMPS
    if arch in ("arm", "arm64", "aarch64"):
        return mnemonic in _ARM_CONDITIONAL_BRANCHES

    if mnemonic.startswith("j") and mnemonic not in ("jmp", "j"):
        return True
    if mnemonic.startswith("b") and mnemonic not in ("b", "br", "bx", "blr", "bl"):
        return True
    return False


def find_nop_sequences(instructions: list[dict]) -> list[tuple[int, int]]:
    """Find sequences of NOP instructions that can be replaced."""
    sequences = []
    i = 0

    while i < len(instructions):
        if instructions[i].get("mnemonic", "").lower() != "nop":
            i += 1
            continue

        start_addr, total_size, i = consume_nop_run(instructions, i)
        if total_size >= 3:
            sequences.append((start_addr, total_size))

    return sequences


def consume_nop_run(instructions: list[dict], i: int) -> tuple[int, int, int]:
    """Accumulate the consecutive NOP run starting at index ``i``."""
    insn = instructions[i]
    start_addr = insn.get("offset", insn.get("addr", 0))
    total_size = insn.get("size", 1)
    j = i + 1
    while j < len(instructions):
        next_insn = instructions[j]
        if next_insn.get("mnemonic", "").lower() != "nop":
            break
        total_size += next_insn.get("size", 1)
        j += 1
    return start_addr, total_size, j


def assemble_bounded(binary: Any, instructions: list[str], max_size: int) -> bytes | None:
    """Assemble ``instructions``; return None if any fails or exceeds size."""
    assembled = b""
    for insn in instructions:
        insn_bytes = binary.assemble(insn)
        if insn_bytes is None:
            return None
        assembled += insn_bytes
        if len(assembled) > max_size:
            return None
    return assembled


__all__ = [
    "assemble_bounded",
    "candidate_block_count",
    "consume_nop_run",
    "find_nop_sequences",
    "is_conditional_jump",
    "select_candidates",
]
