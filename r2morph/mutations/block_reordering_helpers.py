"""Leaf helpers for block reordering selection and cost modeling."""

from __future__ import annotations

import random
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE


def can_reorder_function(func: dict[str, Any], blocks: list[dict[str, Any]]) -> bool:
    """Check if a function is safe to reorder."""
    if len(blocks) < 2:
        return False
    if func.get("size", 0) < 20:
        return False
    if len(blocks) > 50:
        return False
    return True


def generate_reordering(blocks: list[dict[str, Any]]) -> list[int]:
    """Generate a random reordering of basic blocks."""
    indices = list(range(len(blocks)))
    if len(indices) > 1:
        reorderable = indices[1:]
        random.shuffle(reorderable)
        return [indices[0]] + reorderable
    return indices


def calculate_jump_cost(original_order: list[int], new_order: list[int]) -> int:
    """Calculate how many jumps are needed to maintain control flow."""
    jumps_needed = 0
    for i, block_idx in enumerate(new_order[:-1]):
        if new_order[i + 1] != block_idx + 1:
            jumps_needed += 1
    return jumps_needed


def should_consider_function(func: dict[str, Any], blocks: list[dict[str, Any]]) -> bool:
    """Shared conservative guard for function-level block reordering."""
    if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
        return False
    return can_reorder_function(func, blocks)


__all__ = [
    "calculate_jump_cost",
    "can_reorder_function",
    "generate_reordering",
    "should_consider_function",
]
