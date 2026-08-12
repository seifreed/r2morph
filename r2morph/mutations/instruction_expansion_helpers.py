"""Leaf helpers for instruction expansion matching and sizing."""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_HEX_PREFIX_LENGTH = 2
_BINARY_OPERAND_COUNT = 2
_MAX_BYTE_VALUE = 255
_MAX_EXPANDABLE_FUNCTION_SIZE_BYTES = 1000

EXPANSION_RULES: dict[str, dict[tuple[str, ...], list[list[tuple[str, ...]]]]] = {
    "x86": {
        ("imul", "reg", "2"): [
            [("shl", "reg", "1")],
            [("add", "reg", "reg")],
        ],
        ("imul", "reg", "4"): [
            [("shl", "reg", "2")],
        ],
        ("shl", "reg", "1"): [
            [("add", "reg", "reg")],
        ],
    },
    "arm": {
        ("lsl", "reg", "reg", "#1"): [
            [("add", "reg", "reg", "reg")],
        ],
        ("add", "reg", "reg", "#1"): [
            [("adds", "reg", "reg", "#1")],
        ],
        ("mov", "reg", "#0"): [
            [("eor", "reg", "reg", "reg")],
            [("sub", "reg", "reg", "reg")],
        ],
        ("sub", "reg", "reg", "#1"): [
            [("subs", "reg", "reg", "#1")],
        ],
    },
    "arm64": {
        ("lsl", "reg", "reg", "#1"): [
            [("add", "reg", "reg", "reg")],
        ],
        ("mov", "reg", "#0"): [
            [("eor", "reg", "reg", "reg")],
            [("sub", "reg", "reg", "reg")],
        ],
        ("mov", "reg", "xzr"): [
            [("eor", "reg", "reg", "reg")],
        ],
        ("add", "reg", "reg", "#1"): [
            [("sub", "reg", "reg", "#-1")],
        ],
        ("sub", "reg", "reg", "#1"): [
            [("add", "reg", "reg", "#-1")],
        ],
    },
}

_SIZE_SPECIFIERS = frozenset({"dword", "qword", "byte", "word", "ptr"})


def _is_register_operand(operand: str) -> bool:
    if not operand or operand in _SIZE_SPECIFIERS:
        return False
    if operand.startswith(("[", "-[", "0x", "-0x")):
        return False
    if operand.isdigit() or (operand.startswith("-") and operand[1:].isdigit()):
        return False
    if operand.lower().endswith("h") and all(char in "0123456789abcdefABCDEF" for char in operand[:-1]):
        return False
    return not re.fullmatch(r"\[.+\]", operand) and "," not in operand


def _is_immediate_operand(operand: str) -> bool:
    if operand.isdigit():
        return True
    unsigned = operand[1:] if operand.startswith("-") else operand
    if unsigned.startswith("0x") and len(unsigned) > _HEX_PREFIX_LENGTH:
        return all(char in "0123456789abcdefABCDEF" for char in unsigned[2:])
    return unsigned.lower().endswith("h") and all(char in "0123456789abcdefABCDEF" for char in unsigned[:-1])


def _parse_supported_immediate(operand: str) -> int | None:
    try:
        return int(operand, 16) if operand.startswith("0x") else int(operand)
    except ValueError:
        return None


def _second_operand_matches(pattern: str, operand: str) -> bool:
    if pattern == "reg":
        return _is_register_operand(operand)
    if pattern == "0":
        return operand in {"0", "0x0"}
    if not _is_immediate_operand(operand):
        return False
    value = _parse_supported_immediate(operand)
    if pattern == "small_imm":
        return value is not None and 0 <= value <= _MAX_BYTE_VALUE
    if pattern.isdigit() or pattern.startswith("-"):
        return value == int(pattern)
    return True


def _pattern_matches(pattern: tuple[str, ...], mnemonic: str, operands: list[str]) -> bool:
    if mnemonic != pattern[0]:
        return False
    pattern_operands = pattern[1:]
    if not pattern_operands:
        return True
    if pattern_operands[0] != "reg" or not operands or not _is_register_operand(operands[0]):
        return False
    if len(pattern_operands) == 1:
        return True
    if len(pattern_operands) != _BINARY_OPERAND_COUNT:
        return True
    return len(operands) >= _BINARY_OPERAND_COUNT and _second_operand_matches(pattern_operands[1], operands[1])


def match_expansion_pattern(
    instruction: dict[str, Any],
    arch: str,
    expansion_rules: dict[str, dict[tuple[str, ...], list[list[tuple[str, ...]]]]] = EXPANSION_RULES,
) -> list[list[tuple[str, ...]]]:
    """Check if an instruction matches any expansion pattern."""
    arch_family = "x86" if arch in ["x86", "x64"] else arch
    if arch_family not in expansion_rules:
        return []

    disasm = instruction.get("disasm", "").lower()
    parts = disasm.split()
    if not parts:
        return []

    mnemonic = parts[0]
    operands = [p.strip(",") for p in parts[1:]] if len(parts) > 1 else []
    expansions: list[list[tuple[str, ...]]] = []
    for pattern, expansion_list in expansion_rules[arch_family].items():
        if _pattern_matches(pattern, mnemonic, operands):
            expansions.extend(expansion_list)

    return expansions


def build_instruction_from_pattern(pattern: tuple[str, ...], orig_parts: list[str]) -> str | None:
    """Build a concrete instruction from a pattern and original instruction parts."""
    try:
        new_mnemonic = pattern[0]
        new_operands = []

        target_register = None
        if len(orig_parts) > 1:
            candidate = orig_parts[1].strip(",").strip()
            size_specifiers = {"dword", "qword", "byte", "word", "ptr"}
            if candidate and candidate not in size_specifiers and not candidate.startswith("["):
                target_register = candidate
            else:
                return None

        for param in pattern[1:]:
            if param == "reg":
                if target_register:
                    new_operands.append(target_register)
                else:
                    return None
            elif param in ["1", "2", "3", "4", "5", "-1"]:
                new_operands.append(param)
            elif param == "0":
                new_operands.append("0")
            else:
                new_operands.append(param)

        if new_operands:
            return f"{new_mnemonic} {', '.join(new_operands)}"
        return new_mnemonic
    except (ValueError, IndexError, KeyError) as e:
        logger.debug(f"Failed to build instruction from pattern {pattern}: {e}")
        return None


def get_expansion_size_increase(expansion: list[tuple[str, ...]]) -> int:
    """Calculate how many bytes the expansion adds."""
    original_size = 3
    expanded_size = len(expansion) * 3
    return expanded_size - original_size


def is_safe_to_expand(instruction: dict[str, Any], function_size: int) -> bool:
    """Check if it is safe to expand this instruction."""
    insn_type = instruction.get("type", "")
    if insn_type in ["jmp", "cjmp", "call", "ret", "ujmp"]:
        return False

    return function_size <= _MAX_EXPANDABLE_FUNCTION_SIZE_BYTES


__all__ = [
    "EXPANSION_RULES",
    "build_instruction_from_pattern",
    "get_expansion_size_increase",
    "is_safe_to_expand",
    "match_expansion_pattern",
]
