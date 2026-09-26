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
from r2morph.analysis.exception_reader import ExceptionInfoReader
from r2morph.mutations.base import MutationPass
from r2morph.mutations.block_reordering_helpers import (
    calculate_jump_cost,
    can_reorder_function,
    generate_reordering,
    overlaps_exception_frame,
    should_consider_function,
)
from r2morph.mutations.block_reordering_relocation import reorder_function_blocks

logger = logging.getLogger(__name__)


def _read_exception_frames(binary: Any) -> tuple[dict[int, Any] | None, str | None]:
    """Read exception metadata before relocating any function blocks."""
    try:
        reader = ExceptionInfoReader(binary)
        frames = reader.read_exception_frames()
        return frames, reader.read_error
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.debug("Failed to read exception metadata before block reordering: %s", exc)
        return None, "failed to read exception metadata"


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

    def _representative_instruction(
        self, binary: Any, blocks: list[dict[str, Any]]
    ) -> tuple[int, int, bytes, str] | None:
        """Capture one instruction for the relocation evidence record."""
        evidence = None
        if blocks:
            first_block = min(blocks, key=lambda block: int(block["addr"]))
            instructions = binary.r2.cmdj(f"pdbj @ 0x{int(first_block['addr']):x}")
            if isinstance(instructions, list) and instructions and isinstance(instruction := instructions[0], dict):
                address = instruction.get("addr")
                size = instruction.get("size")
                disassembly = instruction.get("disasm")
                raw_bytes = instruction.get("bytes")
                if (
                    isinstance(address, int)
                    and isinstance(size, int)
                    and size > 0
                    and isinstance(disassembly, str)
                    and bool(disassembly)
                    and isinstance(raw_bytes, str)
                ):
                    try:
                        evidence = address, size, bytes.fromhex(raw_bytes), disassembly
                    except ValueError:
                        evidence = None
        return evidence

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
        exception_frames, exception_read_error = _read_exception_frames(binary)
        functions_mutated = 0
        total_blocks_reordered = 0
        functions_processed = 0

        logger.info(f"Block reordering: processing {len(functions)} functions")

        if exception_read_error is not None:
            logger.warning(
                "Block reordering skipped because exception metadata is unavailable: %s",
                exception_read_error,
            )
            return {
                "mutations_applied": 0,
                "functions_mutated": 0,
                "total_blocks_reordered": 0,
                "total_functions": len(functions),
                "functions_processed": 0,
            }

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

            if exception_frames and overlaps_exception_frame(func, exception_frames):
                logger.debug(
                    "Skipping function at 0x%x because it has LSDA-backed exception metadata",
                    int(func["addr"]),
                )
                continue

            functions_processed += 1

            if random.random() > self.probability:
                continue

            evidence = self._representative_instruction(binary, blocks)
            blocks_reordered = reorder_function_blocks(binary, func, blocks, random)
            if blocks_reordered:
                functions_mutated += 1
                total_blocks_reordered += blocks_reordered
                if evidence is not None:
                    address, size, original_bytes, disassembly = evidence
                    mutated_bytes = binary.read_bytes(address, size)
                    self._record_mutation(
                        function_address=int(func["addr"]),
                        start_address=address,
                        end_address=address + size - 1,
                        original_bytes=original_bytes,
                        mutated_bytes=mutated_bytes or original_bytes,
                        original_disasm=disassembly,
                        mutated_disasm=disassembly,
                        mutation_kind="basic_block_reordering",
                        metadata={"blocks_reordered": blocks_reordered},
                    )

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
