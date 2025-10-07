"""
Hot path detection for performance-aware mutations.
"""

import logging
from typing import List

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


class HotPathDetector:
    """
    Detects hot execution paths in binaries.

    Uses heuristics when profiling data unavailable:
    - Functions called frequently
    - Loop headers
    - Error handling paths (cold)
    """

    def __init__(self, binary: Binary):
        """
        Initialize hot path detector.

        Args:
            binary: Binary instance
        """
        self.binary = binary

    def detect_hot_paths(self) -> dict[str, list[int]]:
        """
        Detect likely hot paths using static analysis.

        Returns:
            Dict of function -> hot basic block addresses
        """
        logger.info("Detecting hot paths")

        hot_paths = {}

        functions = self.binary.get_functions()

        for func in functions:
            func_addr = func.get("offset", 0)
            func_name = func.get("name", f"0x{func_addr:x}")

            try:
                bb_json = self.binary.r2.cmd(f"afbj @ 0x{func_addr:x}")
                import json

                bbs = json.loads(bb_json) if bb_json else []

                hot_blocks = self._identify_hot_blocks(bbs)

                if hot_blocks:
                    hot_paths[func_name] = hot_blocks

            except Exception as e:
                logger.debug(f"Failed to analyze {func_name}: {e}")

        return hot_paths

    def _identify_hot_blocks(self, basic_blocks: list[dict]) -> list[int]:
        """
        Identify hot basic blocks heuristically.

        Args:
            basic_blocks: List of basic block dicts

        Returns:
            List of hot block addresses
        """
        hot_blocks = []

        for bb in basic_blocks:
            addr = bb.get("addr", 0)

            if bb.get("type") == "head":
                hot_blocks.append(addr)

            if bb.get("ninstr", 0) > 0 and bb.get("inputs", 0) > 2:
                hot_blocks.append(addr)

        return hot_blocks

    def is_hot_path(self, func_name: str, block_addr: int, hot_paths: dict[str, list[int]]) -> bool:
        """
        Check if a block is on a hot path.

        Args:
            func_name: Function name
            block_addr: Block address
            hot_paths: Hot paths dict

        Returns:
            True if hot
        """
        return block_addr in hot_paths.get(func_name, [])
