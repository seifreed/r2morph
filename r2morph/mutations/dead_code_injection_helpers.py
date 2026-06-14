"""Leaf helpers for dead-code injection analysis and generation."""

from __future__ import annotations

from typing import Any

from r2morph.core.constants import UNCONDITIONAL_TRANSFERS
from r2morph.utils.dead_code import generate_dead_code_for_arch, generate_nop_sequence

PADDING_INSTRUCTIONS = {"nop", "int3", "ud2"}


def find_injection_points(
    instructions: list[dict[str, Any]],
    min_padding_size: int,
    padding_instructions: set[str] | frozenset[str] = PADDING_INSTRUCTIONS,
) -> list[dict[str, Any]]:
    """Find padding-based dead-code injection points in an instruction stream."""
    injection_points = []
    i = 0

    while i < len(instructions):
        insn = instructions[i]
        mnemonic = insn.get("mnemonic", "").lower()

        if mnemonic in padding_instructions:
            padding_start = insn.get("offset", insn.get("addr", 0))
            padding_size = insn.get("size", 1)
            j = i + 1

            while j < len(instructions):
                next_insn = instructions[j]
                next_mnemonic = next_insn.get("mnemonic", "").lower()

                if next_mnemonic not in padding_instructions:
                    break

                padding_size += next_insn.get("size", 1)
                j += 1

            if padding_size >= min_padding_size:
                injection_points.append({"addr": padding_start, "size": padding_size, "type": "padding"})

            i = j
            continue

        if mnemonic in UNCONDITIONAL_TRANSFERS and i + 1 < len(instructions):
            next_insn = instructions[i + 1]
            next_insn.get("offset", next_insn.get("addr", 0))

        i += 1

    return injection_points


def is_safe_injection_point(
    insn: dict[str, Any],
    instructions: list[dict[str, Any]],
    index: int,
    padding_instructions: set[str] | frozenset[str] = PADDING_INSTRUCTIONS,
) -> bool:
    """Return whether an instruction is a safe dead-code injection point."""
    mnemonic = insn.get("mnemonic", "").lower()

    if mnemonic in padding_instructions:
        return True

    if index > 0:
        prev_insn = instructions[index - 1]
        prev_mnemonic = prev_insn.get("mnemonic", "").lower()
        if prev_mnemonic in UNCONDITIONAL_TRANSFERS:
            return mnemonic in padding_instructions

    return False


def generate_dead_code(
    binary: Any,
    code_complexity: str,
) -> list[str]:
    """Generate dead-code instruction templates for the requested architecture."""
    arch_family, bits = binary.get_arch_family()
    return generate_dead_code_for_arch(arch_family, bits, code_complexity)


def generate_dead_code_for_size(
    binary: Any,
    max_size: int,
    func_addr: int,
    code_complexity: str,
) -> bytes | None:
    """Assemble dead-code bytes that fit within `max_size`."""
    arch_family, bits = binary.get_arch_family()

    for _attempt in range(5):
        dead_code_insns = generate_dead_code(binary, code_complexity)

        assemblable_insns = [insn for insn in dead_code_insns if not insn.startswith(".") and not insn.endswith(":")]
        if not assemblable_insns:
            return generate_nop_sequence(arch_family, bits, max_size)

        assembled_bytes: bytes | None = b""
        for insn in assemblable_insns:
            insn_bytes = binary.assemble(insn, func_addr)
            if insn_bytes is None:
                assembled_bytes = None
                break
            assembled_bytes += insn_bytes
            if len(assembled_bytes) > max_size:
                assembled_bytes = None
                break

        if assembled_bytes and len(assembled_bytes) <= max_size:
            if len(assembled_bytes) < max_size:
                padding_size = max_size - len(assembled_bytes)
                assembled_bytes += generate_nop_sequence(arch_family, bits, padding_size)
            return assembled_bytes

    return generate_nop_sequence(arch_family, bits, max_size)


__all__ = [
    "PADDING_INSTRUCTIONS",
    "find_injection_points",
    "generate_dead_code",
    "generate_dead_code_for_size",
    "is_safe_injection_point",
]
