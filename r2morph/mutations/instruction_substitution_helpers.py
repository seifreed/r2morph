"""Leaf helpers for instruction substitution equivalence matching."""

from __future__ import annotations

import logging
import random
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.equivalences import load_equivalence_rules

logger = logging.getLogger(__name__)


def init_substitution_rules() -> tuple[dict[str, list[list[str]]], dict[str, dict[str, int]]]:
    """Load and index substitution rules for all supported architectures."""
    equivalence_groups = {
        "x86": load_equivalence_rules("x86"),
        "arm": load_equivalence_rules("arm"),
        "arm64": load_equivalence_rules("arm64"),
    }

    for arch in equivalence_groups:
        for group in equivalence_groups[arch]:
            random.shuffle(group)

    pattern_to_group: dict[str, dict[str, int]] = {}
    for arch, groups in equivalence_groups.items():
        pattern_to_group.setdefault(arch, {})
        for group_idx, group in enumerate(groups):
            for pattern in group:
                normalized = normalize_instruction(pattern)
                pattern_to_group[arch][normalized] = group_idx

    return equivalence_groups, pattern_to_group


def normalize_instruction(disasm: str) -> str:
    """Normalize instruction text for pattern matching."""
    normalized = " ".join(disasm.lower().split())
    normalized = normalized.replace("0x0", "0")
    normalized = normalized.replace("0x1", "1")
    return normalized


def get_equivalents(
    instruction: dict[str, Any],
    arch: str,
    pattern_to_group: dict[str, dict[str, int]],
    equivalence_groups: dict[str, list[list[str]]],
) -> tuple[str, list[str], int | None]:
    """Return the equivalence group for an instruction if one exists."""
    if arch not in pattern_to_group:
        return ("", [], None)

    disasm = instruction.get("disasm", "")
    normalized = normalize_instruction(disasm)

    if normalized in pattern_to_group[arch]:
        group_idx = pattern_to_group[arch][normalized]
        equivalents = equivalence_groups[arch][group_idx]
        return (normalized, equivalents, group_idx)

    return ("", [], None)


def select_candidates(
    binary: Any,
    functions: list[dict[str, Any]],
    arch_family: str,
    pattern_to_group: dict[str, dict[str, int]],
    equivalence_groups: dict[str, list[list[str]]],
) -> list[tuple[dict, list]]:
    """Select functions that contain substitution candidates."""
    result = []
    for func in functions:
        if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
            continue

        try:
            func_addr = func.get("offset", func.get("addr", 0))
            instructions = binary.get_function_disasm(func_addr)
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
            logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
            continue

        candidates = []
        for insn in instructions:
            original_pattern, equivalents, group_idx = get_equivalents(
                insn, arch_family, pattern_to_group, equivalence_groups
            )
            if equivalents and len(equivalents) > 1:
                candidates.append(insn)
        if candidates:
            result.append((func, candidates))
    return result


__all__ = [
    "get_equivalents",
    "init_substitution_rules",
    "normalize_instruction",
    "select_candidates",
]
