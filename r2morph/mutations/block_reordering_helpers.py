"""Leaf helpers for block reordering selection and cost modeling."""

from __future__ import annotations

from typing import Any

import r2morph.core.randomness as random
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

_MIN_BLOCK_COUNT = 2
_MIN_REORDERABLE_FUNCTION_SIZE_BYTES = 20
_MAX_BLOCK_COUNT = 50


def can_reorder_function(func: dict[str, Any], blocks: list[dict[str, Any]]) -> bool:
    """Check if a function is safe to reorder."""
    if len(blocks) < _MIN_BLOCK_COUNT:
        return False
    if func.get("size", 0) < _MIN_REORDERABLE_FUNCTION_SIZE_BYTES:
        return False
    return len(blocks) <= _MAX_BLOCK_COUNT


def generate_reordering(blocks: list[dict[str, Any]]) -> list[int]:
    """Generate a random reordering of basic blocks."""
    indices = list(range(len(blocks)))
    if len(indices) > 1:
        reorderable = indices[1:]
        random.shuffle(reorderable)
        return [indices[0], *reorderable]
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
