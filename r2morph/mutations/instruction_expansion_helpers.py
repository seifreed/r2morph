"""Leaf helpers for instruction expansion matching and sizing."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

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
    size_specifiers = {"dword", "qword", "byte", "word", "ptr"}

    import re

    def is_register_operand(op: str) -> bool:
        if not op:
            return False
        if op in size_specifiers:
            return False
        if op.startswith("[") or op.startswith("-["):
            return False
        if op.startswith("0x") or op.startswith("-0x"):
            return False
        if op.isdigit() or (op.startswith("-") and op[1:].isdigit()):
            return False
        if op.endswith("h") or op.endswith("H"):
            hex_part = op[:-1]
            if all(c in "0123456789abcdefABCDEF" for c in hex_part):
                return False
        if re.match(r"^\[.+\]$", op):
            return False
        if "," in op:
            return False
        return True

    def is_immediate_operand(op: str) -> bool:
        if not op:
            return False
        if op.isdigit():
            return True
        if op.startswith("-") and len(op) > 1:
            rest = op[1:]
            if rest.isdigit():
                return True
            if rest.startswith("0x") and len(rest) > 2:
                return all(c in "0123456789abcdefABCDEF" for c in rest[2:])
        if op.startswith("0x") and len(op) > 2:
            return all(c in "0123456789abcdefABCDEF" for c in op[2:])
        if op.endswith("h") or op.endswith("H"):
            hex_part = op[:-1]
            return all(c in "0123456789abcdefABCDEF" for c in hex_part)
        return False

    for pattern, expansion_list in expansion_rules[arch_family].items():
        pattern_mnemonic = pattern[0]
        pattern_ops = list(pattern[1:]) if len(pattern) > 1 else []

        if mnemonic != pattern_mnemonic:
            continue

        if not pattern_ops:
            expansions.extend(expansion_list)
            continue

        if len(pattern_ops) == 1 and pattern_ops[0] == "reg":
            if operands and is_register_operand(operands[0]):
                expansions.extend(expansion_list)
            continue

        if len(pattern_ops) >= 1 and pattern_ops[0] == "reg":
            if not operands or not is_register_operand(operands[0]):
                continue

            if len(pattern_ops) == 2:
                second_pattern = pattern_ops[1]
                if len(operands) >= 2:
                    second_op = operands[1]
                    if second_pattern == "reg":
                        if is_register_operand(second_op):
                            expansions.extend(expansion_list)
                    elif second_pattern == "0":
                        if second_op == "0" or second_op == "0x0":
                            expansions.extend(expansion_list)
                    elif second_pattern == "small_imm":
                        if is_immediate_operand(second_op):
                            try:
                                val = int(second_op, 16) if second_op.startswith("0x") else int(second_op)
                                if 0 <= val <= 255:
                                    expansions.extend(expansion_list)
                            except ValueError:
                                pass
                    elif second_pattern.isdigit() or second_pattern.startswith("-"):
                        if is_immediate_operand(second_op):
                            try:
                                expected = int(second_pattern)
                                actual = int(second_op, 16) if second_op.startswith("0x") else int(second_op)
                                if expected == actual:
                                    expansions.extend(expansion_list)
                            except ValueError:
                                pass
                    else:
                        expansions.extend(expansion_list)
            else:
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

    if function_size > 1000:
        return False

    return True


__all__ = [
    "EXPANSION_RULES",
    "build_instruction_from_pattern",
    "get_expansion_size_increase",
    "is_safe_to_expand",
    "match_expansion_pattern",
]
