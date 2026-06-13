"""Hardened control-flow flattening mutation pass."""

from __future__ import annotations

import random
from typing import Any

from r2morph.mutations.hardened_base import HardenedMutationPass


class HardenedControlFlowFlattening(HardenedMutationPass):
    """Hardened control flow flattening with pattern preservation."""

    def __init__(
        self,
        name: str = "hardened_cff",
        enabled: bool = True,
        preserve_patterns: bool = True,
        validate_integrity: bool = True,
        max_functions: int = 5,
        min_blocks: int = 3,
        probability: float = 0.5,
    ):
        super().__init__(
            name=name,
            enabled=enabled,
            preserve_patterns=preserve_patterns,
            validate_integrity=validate_integrity,
        )
        self.max_functions = max_functions
        self.min_blocks = min_blocks
        self.probability = probability

    def apply_hardened(
        self,
        binary: Any,
        cfg: Any,
        safe_regions: list[tuple[int, int]],
        exclusion_zones: list[Any],
    ) -> dict[str, Any]:
        mutations: list[dict[str, Any]] = []
        safe_mutations = 0
        skipped_mutations = 0
        patterns_preserved = 0
        patterns_avoided = 0

        def _build_result() -> dict[str, Any]:
            return {
                "mutations": mutations,
                "safe_mutations": safe_mutations,
                "skipped_mutations": skipped_mutations,
                "patterns_preserved": patterns_preserved,
                "patterns_avoided": patterns_avoided,
            }

        if random.random() > self.probability:
            return _build_result()

        blocks = list(cfg.blocks.items()) if hasattr(cfg, "blocks") else []

        if len(blocks) < self.min_blocks:
            return _build_result()

        for block_addr, block in blocks:
            if self.should_avoid_pattern(block_addr):
                skipped_mutations += 1
                patterns_avoided += 1
                continue

            if self.should_preserve(block_addr):
                patterns_preserved += 1
                continue

            in_safe_region = any(start <= block_addr < end for start, end in safe_regions)

            if not in_safe_region and safe_regions:
                skipped_mutations += 1
                continue

            mutation = self._try_flatten_block(binary, block_addr, block, exclusion_zones)
            if mutation:
                mutations.append(mutation)
                safe_mutations += 1

        return _build_result()

    def _try_flatten_block(
        self,
        binary: Any,
        block_addr: int,
        block: Any,
        exclusion_zones: list[Any],
    ) -> dict[str, Any] | None:
        for zone in exclusion_zones:
            if zone.contains(block_addr):
                return None

        return {
            "type": "cff",
            "address": f"0x{block_addr:x}",
            "description": "Control flow flattening candidate",
        }


def create_hardened_cff_pass(**kwargs: Any) -> HardenedControlFlowFlattening:
    return HardenedControlFlowFlattening(**kwargs)


__all__ = ["HardenedControlFlowFlattening", "create_hardened_cff_pass"]
