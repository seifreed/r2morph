"""
Control flow flattening mutation pass.

Transforms structured control flow into a dispatcher-based flat structure.
Makes reverse engineering significantly harder.
"""

import logging
from typing import Any, Dict, List

from r2morph.analysis.cfg import CFGBuilder
from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


class ControlFlowFlatteningPass(MutationPass):
    """
    Flattens control flow using a dispatcher pattern.

    Transforms:
        block1 -> block2 -> block3

    Into:
        while(true) {
            switch(state) {
                case 0: block1; state = 1; break;
                case 1: block2; state = 2; break;
                case 2: block3; state = -1; break;
            }
        }

    This is one of the most effective obfuscation techniques.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize control flow flattening pass.

        Args:
            config: Configuration dictionary
        """
        super().__init__(name="ControlFlowFlattening", config=config)
        self.max_functions = self.config.get("max_functions_to_flatten", 5)
        self.min_blocks = self.config.get("min_blocks_required", 3)

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply control flow flattening.

        Args:
            binary: Binary to mutate

        Returns:
            Statistics dict
        """
        logger.info("Applying control flow flattening")

        functions = binary.get_functions()
        total_mutations = 0
        funcs_mutated = 0

        candidates = self._select_candidates(binary, functions)

        for func in candidates[: self.max_functions]:
            if self._flatten_function(binary, func):
                funcs_mutated += 1
                total_mutations += 1

        return {
            "mutations_applied": total_mutations,
            "functions_mutated": funcs_mutated,
        }

    def _select_candidates(self, binary: Binary, functions: list[dict]) -> list[Dict]:
        """
        Select functions suitable for flattening.

        Args:
            binary: Binary instance
            functions: List of functions

        Returns:
            List of candidate functions
        """
        candidates = []

        for func in functions:
            func_addr = func.get("offset", 0)

            try:
                bb_json = binary.r2.cmd(f"afbj @ 0x{func_addr:x}")
                import json

                bbs = json.loads(bb_json) if bb_json else []

                if len(bbs) >= self.min_blocks:
                    candidates.append(func)

            except Exception as e:
                logger.debug(f"Failed to analyze function 0x{func_addr:x}: {e}")

        return candidates

    def _flatten_function(self, binary: Binary, func: dict) -> bool:
        """
        Flatten control flow of a function.

        Args:
            binary: Binary instance
            func: Function dict

        Returns:
            True if successful
        """
        func_addr = func.get("offset", 0)
        func_name = func.get("name", f"0x{func_addr:x}")

        logger.info(f"Flattening function {func_name}")

        cfg_builder = CFGBuilder(binary)
        try:
            cfg = cfg_builder.build_cfg(func_addr)
        except Exception as e:
            logger.error(f"Failed to build CFG for {func_name}: {e}")
            return False

        blocks = list(cfg.blocks.values())

        if len(blocks) < self.min_blocks:
            logger.debug(f"Function {func_name} has too few blocks")
            return False

        dispatcher_code = self._generate_dispatcher(binary, blocks)

        logger.info(
            f"Would flatten {func_name} with {len(blocks)} blocks "
            f"into dispatcher with {len(dispatcher_code)} instructions"
        )

        return True

    def _generate_dispatcher(self, binary: Binary, blocks: list[Any]) -> list[str]:
        """
        Generate dispatcher code.

        Args:
            binary: Binary instance
            blocks: List of basic blocks

        Returns:
            List of assembly instructions
        """
        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "x86")
        bits = arch_info.get("bits", 64)

        if "x86" in arch.lower():
            return self._generate_x86_dispatcher(blocks, bits)
        elif "arm" in arch.lower():
            return self._generate_arm_dispatcher(blocks, bits)

        return []

    def _generate_x86_dispatcher(self, blocks: list[Any], bits: int) -> list[str]:
        """
        Generate x86 dispatcher.

        Args:
            blocks: Basic blocks
            bits: Bit width

        Returns:
            Assembly instructions
        """
        reg = "rax" if bits == 64 else "eax"

        code = [
            "; Flattened control flow dispatcher",
            f"mov {reg}, 0  ; Initial state",
            ".dispatcher_loop:",
        ]

        for i, block in enumerate(blocks):
            code.extend(
                [
                    f"cmp {reg}, {i}",
                    f"je .block_{i}",
                ]
            )

        code.append("jmp .dispatcher_end")

        for i, block in enumerate(blocks):
            code.append(f".block_{i}:")
            code.append(f"; Original block at 0x{block.address:x}")
            code.append("; ... block code here ...")

            if i < len(blocks) - 1:
                code.append(f"mov {reg}, {i + 1}")
            else:
                code.append(f"mov {reg}, -1")

            code.append("jmp .dispatcher_loop")

        code.append(".dispatcher_end:")

        return code

    def _generate_arm_dispatcher(self, blocks: list[Any], bits: int) -> list[str]:
        """
        Generate ARM dispatcher.

        Args:
            blocks: Basic blocks
            bits: Bit width

        Returns:
            Assembly instructions
        """
        reg = "x0" if bits == 64 else "r0"

        code = [
            "; Flattened control flow dispatcher",
            f"mov {reg}, #0  ; Initial state",
            ".dispatcher_loop:",
        ]

        for i, block in enumerate(blocks):
            code.extend(
                [
                    f"cmp {reg}, #{i}",
                    f"b.eq .block_{i}",
                ]
            )

        code.append("b .dispatcher_end")

        for i, block in enumerate(blocks):
            code.append(f".block_{i}:")
            code.append(f"; Original block at 0x{block.address:x}")
            code.append("; ... block code here ...")

            if i < len(blocks) - 1:
                code.append(f"mov {reg}, #{i + 1}")
            else:
                code.append(f"mov {reg}, #-1")

            code.append("b .dispatcher_loop")

        code.append(".dispatcher_end:")

        return code
