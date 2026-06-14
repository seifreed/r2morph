"""Leaf helpers for register substitution analysis."""

from __future__ import annotations

import logging
import random
import re
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

logger = logging.getLogger(__name__)

REGISTER_CLASSES: dict[str, dict[str, list[str]]] = {
    "x86": {
        "gp32": ["eax", "ebx", "ecx", "edx", "esi", "edi"],
        "caller_saved": ["eax", "ecx", "edx"],
        "callee_saved": ["ebx", "esi", "edi"],
    },
    "x64": {
        "gp64": [
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
        ],
        "caller_saved": ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
        "callee_saved": ["rbx", "r12", "r13", "r14", "r15"],
    },
    "arm": {
        "gp": ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
        "caller_saved": ["r0", "r1", "r2", "r3"],
        "callee_saved": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
    },
    "arm64": {
        "gp64": [
            "x0",
            "x1",
            "x2",
            "x3",
            "x4",
            "x5",
            "x6",
            "x7",
            "x8",
            "x9",
            "x10",
            "x11",
            "x12",
            "x13",
            "x14",
            "x15",
            "x16",
            "x17",
            "x18",
            "x19",
            "x20",
            "x21",
            "x22",
            "x23",
            "x24",
            "x25",
            "x26",
            "x27",
            "x28",
        ],
        "gp32": [
            "w0",
            "w1",
            "w2",
            "w3",
            "w4",
            "w5",
            "w6",
            "w7",
            "w8",
            "w9",
            "w10",
            "w11",
            "w12",
            "w13",
            "w14",
            "w15",
            "w16",
            "w17",
            "w18",
            "w19",
            "w20",
            "w21",
            "w22",
            "w23",
            "w24",
            "w25",
            "w26",
            "w27",
            "w28",
        ],
        "caller_saved": [
            "x0",
            "x1",
            "x2",
            "x3",
            "x4",
            "x5",
            "x6",
            "x7",
            "x8",
            "x9",
            "x10",
            "x11",
            "x12",
            "x13",
            "x14",
            "x15",
            "x16",
            "x17",
            "x30",
        ],
        "callee_saved": ["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28"],
    },
}

REGISTER_SIZES: dict[str, int] = {
    "al": 8,
    "bl": 8,
    "cl": 8,
    "dl": 8,
    "ah": 8,
    "bh": 8,
    "ch": 8,
    "dh": 8,
    "spl": 8,
    "bpl": 8,
    "sil": 8,
    "dil": 8,
    "r8b": 8,
    "r9b": 8,
    "r10b": 8,
    "r11b": 8,
    "r12b": 8,
    "r13b": 8,
    "r14b": 8,
    "r15b": 8,
    "ax": 16,
    "bx": 16,
    "cx": 16,
    "dx": 16,
    "sp": 16,
    "bp": 16,
    "si": 16,
    "di": 16,
    "r8w": 16,
    "r9w": 16,
    "r10w": 16,
    "r11w": 16,
    "r12w": 16,
    "r13w": 16,
    "r14w": 16,
    "r15w": 16,
    "eax": 32,
    "ebx": 32,
    "ecx": 32,
    "edx": 32,
    "esp": 32,
    "ebp": 32,
    "esi": 32,
    "edi": 32,
    "r8d": 32,
    "r9d": 32,
    "r10d": 32,
    "r11d": 32,
    "r12d": 32,
    "r13d": 32,
    "r14d": 32,
    "r15d": 32,
    "rax": 64,
    "rbx": 64,
    "rcx": 64,
    "rdx": 64,
    "rsp": 64,
    "rbp": 64,
    "rsi": 64,
    "rdi": 64,
    "r8": 64,
    "r9": 64,
    "r10": 64,
    "r11": 64,
    "r12": 64,
    "r13": 64,
    "r14": 64,
    "r15": 64,
}

_X86_REGISTER_FAMILIES: dict[str, list[str]] = {
    "a": ["al", "ah", "ax", "eax", "rax"],
    "b": ["bl", "bh", "bx", "ebx", "rbx"],
    "c": ["cl", "ch", "cx", "ecx", "rcx"],
    "d": ["dl", "dh", "dx", "edx", "rdx"],
    "si": ["sil", "si", "esi", "rsi"],
    "di": ["dil", "di", "edi", "rdi"],
    "sp": ["spl", "sp", "esp", "rsp"],
    "bp": ["bpl", "bp", "ebp", "rbp"],
}


def get_register_class(arch: str) -> dict[str, list[str]]:
    """Get register classes for architecture."""
    if arch in ["x86", "x64"]:
        arch_family = arch
    elif arch == "arm64":
        arch_family = "arm64"
    elif arch == "arm":
        arch_family = "arm"
    else:
        return {}
    return REGISTER_CLASSES.get(arch_family, {})


def find_substitution_candidates(instructions: list[dict[str, Any]], arch: str) -> list[tuple[str, str]]:
    """Find valid register substitution opportunities."""
    register_classes = get_register_class(arch)
    if not register_classes:
        return []

    used_registers = set()
    for insn in instructions:
        disasm = insn.get("disasm", "").lower()
        for reg_class in register_classes.values():
            for reg in reg_class:
                if reg in disasm:
                    used_registers.add(reg)

    caller_saved = set(register_classes.get("caller_saved", []))
    unused = sorted(caller_saved - used_registers)
    random.shuffle(unused)

    candidates = []
    for i, used_reg in enumerate(sorted(used_registers & caller_saved)):
        if i < len(unused):
            candidates.append((used_reg, unused[i]))
    return candidates


def count_register_uses(instructions: list[dict[str, Any]], register: str) -> int:
    """Count how many times a register is used."""
    count = 0
    for insn in instructions:
        disasm = insn.get("disasm", "").lower()
        if register in disasm:
            count += 1
    return count


def is_safe_size_extension_substitution(disasm: str, orig_reg: str, subst_reg: str) -> bool:
    """Check if register substitution is safe for movzx/movsx instructions."""
    parts = disasm.split(",")
    if len(parts) < 2:
        return False

    dest = parts[0].split()[-1].strip()
    source = parts[1].strip()

    orig_size = REGISTER_SIZES.get(orig_reg, 0)
    subst_size = REGISTER_SIZES.get(subst_reg, 0)
    if orig_size == 0 or subst_size == 0:
        return False
    if orig_size != subst_size:
        logger.debug(
            f"Skipping {disasm}: {orig_reg}({orig_size}b) -> {subst_reg}({subst_size}b) size mismatch for movzx/movsx"
        )
        return False

    source_family = None
    orig_family = None
    subst_family = None
    for family, regs in _X86_REGISTER_FAMILIES.items():
        if source in regs:
            source_family = family
        if orig_reg in regs:
            orig_family = family
        if subst_reg in regs:
            subst_family = family

    if orig_reg == dest:
        if subst_family and orig_family and subst_family == orig_family:
            logger.debug(f"Skipping dest substitution {disasm}: {subst_reg} is in same family as {dest}")
            return False
    elif orig_reg == source:
        if subst_family and source_family and subst_family == source_family:
            logger.debug(
                f"Skipping source substitution {disasm}: {subst_reg} would be in same family as source {source}"
            )
            return False

    dest_mem_size = REGISTER_SIZES.get(dest, 0)
    source_mem_size = REGISTER_SIZES.get(source, 0)
    if dest_mem_size > 0 and source_mem_size > 0:
        if dest_mem_size < source_mem_size:
            logger.debug(
                f"Skipping size extension: dest size ({dest_mem_size}) must be >= source size ({source_mem_size})"
            )
            return False
        if dest_mem_size == source_mem_size:
            logger.debug(
                f"Skipping size extension: dest size ({dest_mem_size}) equals source size ({source_mem_size})"
            )
            return False

    return True


def is_safe_lea_substitution(disasm: str, orig_reg: str, subst_reg: str) -> bool:
    """Check if register substitution is safe for LEA."""
    parts = disasm.split(",", 1)
    if len(parts) < 2:
        return False

    dest = parts[0].split()[-1].strip()
    calculation_part = parts[1].strip()

    if orig_reg == dest:
        return True

    if "[" in calculation_part and "]" in calculation_part:
        calc_inner = calculation_part.split("[")[1].split("]")[0]
        if re.search(r"\b" + re.escape(orig_reg) + r"\b", calc_inner):
            logger.debug(f"Skipping LEA substitution: {orig_reg} in address calculation of '{disasm}'")
            return False

    return True


def select_candidates(
    binary: Any,
    functions: list[dict[str, Any]],
    arch: str,
    probability: float,
    max_substitutions: int,
) -> list[tuple[dict, list[dict], list[tuple[str, str]]]]:
    """Select functions with substitution candidates."""
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
        candidates = find_substitution_candidates(instructions, arch)
        if not candidates:
            continue
        if random.random() > probability:
            continue
        num_substitutions = min(max_substitutions, len(candidates))
        selected = random.sample(candidates, num_substitutions)
        result.append((func, instructions, selected))
    return result


__all__ = [
    "REGISTER_CLASSES",
    "REGISTER_SIZES",
    "count_register_uses",
    "find_substitution_candidates",
    "get_register_class",
    "is_safe_lea_substitution",
    "is_safe_size_extension_substitution",
    "select_candidates",
]
