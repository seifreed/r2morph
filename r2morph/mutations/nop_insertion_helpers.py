"""Leaf helpers for NOP insertion candidate analysis and generation."""

from __future__ import annotations

import logging
from typing import Any

import r2morph.core.randomness as random
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

logger = logging.getLogger(__name__)

_X86_32_BITS = 32
_X86_64_BITS = 64
_SHORT_PATTERN_SIZE = 3
_MEDIUM_PATTERN_SIZE = 4
_LONG_PATTERN_SIZE = 5
_BINARY_OPERAND_COUNT = 2
_TERNARY_OPERAND_COUNT = 3

NOP_EQUIVALENTS_BASE = {
    "x86": [
        "xchg eax, eax",
        "xchg ebx, ebx",
        "xchg ecx, ecx",
        "xchg edx, edx",
        "lea eax, [eax]",
        "lea ebx, [ebx]",
        "lea ecx, [ecx]",
        "lea edx, [edx]",
        "mov eax, eax",
        "mov ebx, ebx",
        "mov ecx, ecx",
        "mov edx, edx",
        "xchg rax, rax",
        "xchg rbx, rbx",
        "xchg rcx, rcx",
        "xchg rdx, rdx",
        "lea rax, [rax]",
        "lea rbx, [rbx]",
        "lea rcx, [rcx]",
        "lea rdx, [rdx]",
    ],
    "arm": [
        "mov r0, r0",
        "mov r1, r1",
        "mov r2, r2",
        "mov r3, r3",
        "orr r0, r0, #0",
        "orr r1, r1, #0",
        "add r0, r0, #0",
        "add r1, r1, #0",
        "sub r0, r0, #0",
        "lsl r0, r0, #0",
        "lsl r1, r1, #0",
    ],
}

REGISTERS_32BIT = ["eax", "ebx", "ecx", "edx", "esi", "edi"]
REGISTERS_64BIT = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi"]
CALLER_SAVED_32BIT = {"eax", "ecx", "edx"}
CALLER_SAVED_ARM32 = {"r0", "r1", "r2", "r3"}
CALLER_SAVED_64BIT = {
    "rax",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
}


def init_nop_equivalents() -> dict[str, list[str]]:
    """Initialize and shuffle NOP equivalents."""
    nop_equivalents = {}
    for arch, patterns in NOP_EQUIVALENTS_BASE.items():
        shuffled = patterns.copy()
        random.shuffle(shuffled)
        nop_equivalents[arch] = shuffled
    return nop_equivalents


def is_safe_self_redundancy(register: str, bits: int) -> bool:
    """Restrict stable NOP substitution to caller-saved self-operations."""
    if bits == _X86_64_BITS:
        return register in CALLER_SAVED_64BIT
    return register in CALLER_SAVED_32BIT


def _binary_operands(disasm: str) -> tuple[str, str] | None:
    parts = disasm.split(",")
    if len(parts) != _BINARY_OPERAND_COUNT:
        return None
    mnemonic_parts = parts[0].split()
    if len(mnemonic_parts) < _BINARY_OPERAND_COUNT:
        return None
    return mnemonic_parts[-1].strip(), parts[1].strip()


def _is_x86_redundant(disasm: str, bits: int) -> bool:
    operands = _binary_operands(disasm)
    if operands is None or not any(mnemonic in disasm for mnemonic in ("mov", "lea", "xchg")):
        return False
    destination, source = operands
    if "lea" in disasm:
        source = source.strip("[]")
    return source == destination and is_safe_self_redundancy(destination, bits)


def _is_arm_redundant(disasm: str) -> bool:
    if disasm == "nop":
        return True
    normalized = disasm.replace("#", "")
    if normalized.startswith("mov "):
        operands = _binary_operands(normalized)
        return operands is not None and operands[0] == operands[1]
    if normalized.startswith(("add ", "sub ")):
        parts = normalized.split(",")
        return len(parts) == _TERNARY_OPERAND_COUNT and parts[2].strip() in ("0", "0x0")
    return False


def _is_redundant_instruction(insn: dict[str, Any], arch_family: str, bits: int) -> bool:
    if insn.get("type", "") in ("jmp", "cjmp", "call", "ret", "ujmp", "rcall"):
        return False
    disasm = insn.get("disasm", "").lower()
    if arch_family == "x86":
        return _is_x86_redundant(disasm, bits)
    if arch_family == "arm":
        return _is_arm_redundant(disasm)
    return False


def generate_jmp_dead_code(size: int, bits: int, binary: Any, function_addr: int | None = None) -> bytes | None:
    """Generate jmp + dead code pattern."""
    regs = REGISTERS_32BIT if bits == _X86_32_BITS else REGISTERS_64BIT

    patterns = []
    if size == _SHORT_PATTERN_SIZE and bits == _X86_32_BITS:
        patterns = [
            f"jmp 1; inc {random.choice(regs)}",
            f"jmp 1; push {random.choice(regs)}",
            f"jmp 1; pop {random.choice(regs)}",
        ]
    elif size == _MEDIUM_PATTERN_SIZE and bits == _X86_32_BITS:
        patterns = [
            f"jmp 2; inc {random.choice(regs)}; inc {random.choice(regs)}",
            f"jmp 2; push {random.choice(regs)}; pop {random.choice(regs)}",
            f"jmp 2; pop {random.choice(regs)}; push {random.choice(regs)}",
        ]
    elif size == _SHORT_PATTERN_SIZE and bits == _X86_64_BITS:
        patterns = [
            f"jmp 1; push {random.choice(regs)}",
            f"jmp 1; pop {random.choice(regs)}",
        ]
    elif size == _MEDIUM_PATTERN_SIZE and bits == _X86_64_BITS:
        patterns = [
            f"jmp 2; pop {random.choice(regs)}; pop {random.choice(regs)}",
            f"jmp 2; push {random.choice(regs)}; push {random.choice(regs)}",
            f"jmp 2; push {random.choice(regs)}; pop {random.choice(regs)}",
            f"jmp 2; pop {random.choice(regs)}; push {random.choice(regs)}",
        ]
    elif size == _LONG_PATTERN_SIZE and bits == _X86_64_BITS:
        patterns = [
            f"jmp 3; push {random.choice(regs)}; push {random.choice(regs)}",
            f"jmp 3; pop {random.choice(regs)}; pop {random.choice(regs)}",
        ]

    if not patterns:
        return None

    random.shuffle(patterns)
    for pattern in patterns:
        try:
            instructions = [i.strip() for i in pattern.split(";")]
            all_bytes = b""
            for inst in instructions:
                inst_bytes = binary.assemble(inst, function_addr)
                if inst_bytes is None:
                    break
                all_bytes += inst_bytes
            if all_bytes and len(all_bytes) == size:
                return all_bytes
        except (ValueError, OSError, BrokenPipeError) as e:
            logger.debug(f"Failed to assemble jmp pattern '{pattern}': {e}")
            continue

    return None


def select_candidates(
    binary: Any,
    functions: list[dict[str, Any]],
    arch_family: str,
    bits: int,
    max_nops: int,
) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
    """Iterate functions, get disasm, and filter redundant instruction candidates."""
    result = []
    for func in functions:
        if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
            continue

        func_addr = func.get("offset", func.get("addr", 0))
        try:
            instructions = binary.get_function_disasm(func_addr)
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
            logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
            continue

        candidates = [insn for insn in instructions if _is_redundant_instruction(insn, arch_family, bits)]

        nops_to_insert = min(max_nops, len(candidates))
        selected = random.sample(candidates, min(nops_to_insert, len(candidates)))
        if selected:
            result.append((func, selected))
    return result


__all__ = [
    "CALLER_SAVED_32BIT",
    "CALLER_SAVED_64BIT",
    "CALLER_SAVED_ARM32",
    "NOP_EQUIVALENTS_BASE",
    "generate_jmp_dead_code",
    "init_nop_equivalents",
    "is_safe_self_redundancy",
    "select_candidates",
]
