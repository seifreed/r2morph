"""
Basic block reordering mutation pass.

Reorders basic blocks within functions while preserving control flow.
This is a powerful obfuscation technique that changes code layout without
affecting program semantics.
"""

import logging
import random
from typing import Any, Dict, List

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass

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
        """
        Check if a function is safe to reorder.

        Args:
            func: Function dictionary
            blocks: Basic blocks in the function

        Returns:
            True if function can be safely reordered
        """
        if len(blocks) < 2:
            return False

        if func.get("size", 0) < 20:
            return False

        if len(blocks) > 50:
            return False

        return True

    def _generate_reordering(self, blocks: list[dict[str, Any]]) -> list[int]:
        """
        Generate a random reordering of basic blocks.

        Args:
            blocks: List of basic blocks

        Returns:
            List of indices representing new order
        """
        indices = list(range(len(blocks)))

        if len(indices) > 1:
            reorderable = indices[1:]
            random.shuffle(reorderable)
            return [indices[0]] + reorderable

        return indices

    def _calculate_jump_cost(self, original_order: list[int], new_order: list[int]) -> int:
        """
        Calculate how many jumps we need to add to maintain control flow.

        Args:
            original_order: Original block order
            new_order: New block order

        Returns:
            Number of additional jumps needed
        """
        jumps_needed = 0

        for i, block_idx in enumerate(new_order[:-1]):
            if new_order[i + 1] != block_idx + 1:
                jumps_needed += 1

        return jumps_needed

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply block reordering mutations to the binary.

        Args:
            binary: Binary instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            binary.analyze()

        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0
        total_blocks_reordered = 0
        functions_processed = 0

        logger.info(f"Block reordering: processing {len(functions)} functions")

        for func in functions:
            if functions_processed >= self.max_functions:
                break

            try:
                blocks = binary.get_basic_blocks(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get blocks for {func.get('name')}: {e}")
                continue

            if not self._can_reorder_function(func, blocks):
                continue

            functions_processed += 1

            if random.random() > self.probability:
                continue

            original_order = list(range(len(blocks)))
            new_order = self._generate_reordering(blocks)

            if new_order == original_order:
                continue

            self._calculate_jump_cost(original_order, new_order)

            logger.debug(f"Attempting to reorder function {func.get('name')}: {len(blocks)} blocks")

            blocks_swapped = 0

            for i in range(len(blocks) - 1):
                if blocks_swapped >= 3:
                    break

                block1 = blocks[i]
                block2 = blocks[i + 1]

                addr1 = block1.get("addr", 0)
                addr2 = block2.get("addr", 0)
                size1 = block1.get("size", 0)
                size2 = block2.get("size", 0)

                if size1 < 5 or size2 < 5 or size1 > 200 or size2 > 200:
                    continue

                if addr2 != addr1 + size1:
                    continue

                if size1 == size2 and random.random() < 0.5:
                    try:
                        bytes1_hex = binary.r2.cmd(f"p8 {size1} @ 0x{addr1:x}")
                        bytes2_hex = binary.r2.cmd(f"p8 {size2} @ 0x{addr2:x}")

                        if bytes1_hex and bytes2_hex:
                            bytes1 = bytes.fromhex(bytes1_hex.strip())
                            bytes2 = bytes.fromhex(bytes2_hex.strip())

                            if binary.write_bytes(addr1, bytes2) and binary.write_bytes(
                                addr2, bytes1
                            ):
                                logger.info(
                                    f"Swapped blocks at 0x{addr1:x} <-> 0x{addr2:x} "
                                    f"({size1} bytes each)"
                                )
                                blocks_swapped += 1
                                mutations_applied += 1
                    except Exception as e:
                        logger.debug(f"Failed to swap blocks: {e}")

            jumps_inserted = 0

            for i in range(len(blocks) - 1):
                if jumps_inserted >= 2:
                    break

                block = blocks[i]
                next_block = blocks[i + 1]

                addr = block.get("addr", 0)
                size = block.get("size", 0)
                next_block.get("addr", 0)

                if size < 10:
                    continue

                try:
                    last_insn = binary.r2.cmdj(f"pdj 1 @ 0x{addr + size - 5:x}")
                    if last_insn and len(last_insn) > 0:
                        insn_type = last_insn[0].get("type", "")
                        if insn_type in ["jmp", "cjmp", "ret", "call"]:
                            continue
                except:
                    continue

                if random.random() > 0.3:
                    continue

                if i + 2 < len(blocks):
                    target_block = blocks[i + 2]
                    target_addr = target_block.get("addr", 0)

                    jmp_insn = f"jmp 0x{target_addr:x}"
                    jmp_bytes = binary.assemble(jmp_insn, func["addr"])

                    if jmp_bytes and len(jmp_bytes) <= 5:
                        write_addr = addr + size - len(jmp_bytes)

                        try:
                            if binary.write_bytes(write_addr, jmp_bytes):
                                logger.info(f"Inserted jump at 0x{write_addr:x}: {jmp_insn}")
                                jumps_inserted += 1
                                mutations_applied += 1
                        except Exception as e:
                            logger.debug(f"Failed to insert jump: {e}")

            if blocks_swapped > 0 or jumps_inserted > 0:
                total_blocks_reordered += blocks_swapped * 2
                functions_mutated += 1
                logger.info(
                    f"Reordered {blocks_swapped} block pairs and inserted {jumps_inserted} jumps "
                    f"in {func.get('name')}"
                )
            else:
                logger.debug(f"Could not reorder {func.get('name')}: no suitable blocks found")

        logger.info(
            f"Block reordering complete: {functions_mutated} functions mutated, "
            f"{total_blocks_reordered} blocks reordered"
        )

        return {
            "mutations_applied": mutations_applied,
            "functions_mutated": functions_mutated,
            "total_blocks_reordered": total_blocks_reordered,
            "total_functions": len(functions),
            "functions_processed": functions_processed,
        }
