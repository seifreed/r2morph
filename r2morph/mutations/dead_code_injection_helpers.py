"""Leaf helpers for safe executable NOP-padding replacement."""

from __future__ import annotations

from typing import Any

import r2morph.core.randomness as random
from r2morph.core.constants import UNCONDITIONAL_TRANSFERS
from r2morph.utils.dead_code import generate_dead_code_for_arch, generate_nop_sequence

PADDING_INSTRUCTIONS = {"nop"}
_BITS_64 = 64


def instruction_mnemonic(insn: dict[str, Any]) -> str:
    """Mnemonic of a radare2 disassembly record.

    ``get_function_disasm`` records expose the mnemonic under ``opcode`` (with
    ``disasm`` as a fallback), not ``mnemonic``.
    """
    text = insn.get("opcode") or insn.get("disasm") or ""
    return text.split()[0].lower() if text else ""


def find_injection_points(
    instructions: list[dict[str, Any]],
    min_padding_size: int,
    padding_instructions: set[str] | frozenset[str] = PADDING_INSTRUCTIONS,
) -> list[dict[str, Any]]:
    """Find executable NOP runs that can be replaced without changing state."""
    injection_points = []
    i = 0

    while i < len(instructions):
        insn = instructions[i]

        if instruction_mnemonic(insn) in padding_instructions:
            padding_start = insn.get("addr", insn.get("offset", 0))
            padding_size = insn.get("size", 1)
            j = i + 1

            while j < len(instructions):
                if instruction_mnemonic(instructions[j]) not in padding_instructions:
                    break

                padding_size += instructions[j].get("size", 1)
                j += 1

            if padding_size >= min_padding_size:
                injection_points.append({"addr": padding_start, "size": padding_size, "type": "padding"})

            i = j
            continue

        i += 1

    return injection_points


def is_safe_injection_point(
    insn: dict[str, Any],
    instructions: list[dict[str, Any]],
    index: int,
    padding_instructions: set[str] | frozenset[str] = PADDING_INSTRUCTIONS,
) -> bool:
    """Return whether an instruction is a safe dead-code injection point."""
    if instruction_mnemonic(insn) in padding_instructions:
        return True

    if index > 0:
        prev_mnemonic = instruction_mnemonic(instructions[index - 1])
        if prev_mnemonic in UNCONDITIONAL_TRANSFERS:
            return instruction_mnemonic(insn) in padding_instructions

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
    """Assemble a state-preserving replacement for executable NOP padding."""
    arch_family, bits = binary.get_arch_family()
    if code_complexity == "simple":
        return generate_nop_sequence(arch_family, bits, max_size)

    if "x86" in arch_family.lower():
        registers = ["rbx", "rcx", "rdx", "rsi", "rdi"] if bits == _BITS_64 else ["ebx", "ecx", "edx", "esi", "edi"]
    elif "arm" in arch_family.lower():
        registers = ["x9", "x10", "x11"] if bits == _BITS_64 else ["r4", "r5", "r6"]
    else:
        return generate_nop_sequence(arch_family, bits, max_size)

    register = random.choice(registers)
    instructions = [f"mov {register}, {register}"]
    if code_complexity == "complex":
        second_register = random.choice([candidate for candidate in registers if candidate != register])
        instructions.append(f"mov {second_register}, {second_register}")

    replacement = b""
    for instruction in instructions:
        encoded = binary.assemble(instruction, func_addr)
        if encoded is None:
            return generate_nop_sequence(arch_family, bits, max_size)
        if len(replacement) + len(encoded) > max_size:
            break
        replacement += encoded

    if not replacement:
        return generate_nop_sequence(arch_family, bits, max_size)
    return replacement + generate_nop_sequence(arch_family, bits, max_size - len(replacement))


__all__ = [
    "PADDING_INSTRUCTIONS",
    "find_injection_points",
    "generate_dead_code",
    "generate_dead_code_for_size",
    "is_safe_injection_point",
]
