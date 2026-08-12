"""
Basic block reordering mutation pass.

Reorders basic blocks within functions while preserving control flow.
This is a powerful obfuscation technique that changes code layout without
affecting program semantics.
"""

from __future__ import annotations

import logging
from typing import Any

import r2morph.core.randomness as random
from r2morph.mutations.base import MutationPass
from r2morph.mutations.block_reordering_helpers import (
    calculate_jump_cost,
    can_reorder_function,
    generate_reordering,
    should_consider_function,
)
from r2morph.mutations.block_reordering_relocation import reorder_function_blocks

logger = logging.getLogger(__name__)


class BlockReorderingPass(MutationPass):
    """
    Mutation pass that reorders basic blocks within functions.

    This mutation changes the physical layout of code by reordering basic
    blocks and adding unconditional jumps to maintain control flow.

    Example:
        Original:       After reordering:
        BB1             BB3
        BB2             JMP BB1
        BB3             BB1
                        JMP BB2
                        BB2

    Config options:
        - probability: Probability of reordering a function (default: 0.3)
        - max_functions: Maximum functions to reorder (default: 10)
        - preserve_fallthrough: Try to preserve fall-through edges (default: True)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize block reordering pass.

        Args:
            config: Configuration dictionary
        """
        super().__init__(name="BlockReordering", config=config)
        self.probability = self.config.get("probability", 0.3)
        self.max_functions = self.config.get("max_functions", 10)
        self.preserve_fallthrough = self.config.get("preserve_fallthrough", True)

    def _can_reorder_function(self, func: dict[str, Any], blocks: list[dict[str, Any]]) -> bool:
        return can_reorder_function(func, blocks)

    def _generate_reordering(self, blocks: list[dict[str, Any]]) -> list[int]:
        return generate_reordering(blocks)

    def _calculate_jump_cost(self, original_order: list[int], new_order: list[int]) -> int:
        return calculate_jump_cost(original_order, new_order)

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply block reordering mutations to the binary.

        Blocks are relocated as whole units with every control transfer
        re-encoded for the new layout (see ``block_reordering_relocation``).
        Fall-through edges are always preserved with an explicit jump when the
        successor is no longer physically adjacent; a function that cannot be
        relocated byte-correctly is left untouched.

        Args:
            binary: Any instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        self._ensure_analyzed(binary)
        self._reset_random()

        functions = binary.get_functions()
        functions_mutated = 0
        total_blocks_reordered = 0
        functions_processed = 0

        logger.info(f"Block reordering: processing {len(functions)} functions")

        for func in functions:
            if functions_processed >= self.max_functions:
                break

            try:
                blocks = binary.get_basic_blocks(func["addr"])
            except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
                logger.debug(f"Failed to get blocks for {func.get('name')}: {e}")
                continue

            if not should_consider_function(func, blocks):
                continue

            functions_processed += 1

            if random.random() > self.probability:
                continue

            blocks_reordered = reorder_function_blocks(binary, func, blocks, random)
            if blocks_reordered:
                functions_mutated += 1
                total_blocks_reordered += blocks_reordered

        logger.info(
            f"Block reordering complete: {functions_mutated} functions reordered, "
            f"{total_blocks_reordered} blocks relocated"
        )

        return {
            "mutations_applied": functions_mutated,
            "functions_mutated": functions_mutated,
            "total_blocks_reordered": total_blocks_reordered,
            "total_functions": len(functions),
            "functions_processed": functions_processed,
        }
