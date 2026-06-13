"""Hardened opaque predicate mutation pass."""

from __future__ import annotations

import random
from typing import Any

from r2morph.mutations.hardened_base import HardenedMutationPass


class HardenedOpaquePredicates(HardenedMutationPass):
    """Hardened opaque predicate insertion with pattern preservation."""

    def __init__(
        self,
        name: str = "hardened_opaque",
        enabled: bool = True,
        preserve_patterns: bool = True,
        validate_integrity: bool = True,
        density: float = 0.3,
    ):
        super().__init__(
            name=name,
            enabled=enabled,
            preserve_patterns=preserve_patterns,
            validate_integrity=validate_integrity,
        )
        self.density = density

    def apply_hardened(
        self,
        binary: Any,
        cfg: Any,
        safe_regions: list[tuple[int, int]],
        exclusion_zones: list[Any],
    ) -> dict[str, Any]:
        all_mutations: list[dict[str, Any]] = []
        safe_mutations = 0
        skipped_mutations = 0
        patterns_preserved = 0
        patterns_avoided = 0

        blocks = list(cfg.blocks.items()) if hasattr(cfg, "blocks") else []

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

            found_mutations = self._find_opaque_opportunities(binary, block_addr, block, exclusion_zones)
            all_mutations.extend(found_mutations)
            safe_mutations += len(found_mutations)

        return {
            "mutations": all_mutations,
            "safe_mutations": safe_mutations,
            "skipped_mutations": skipped_mutations,
            "patterns_preserved": patterns_preserved,
            "patterns_avoided": patterns_avoided,
        }

    def _find_opaque_opportunities(
        self,
        binary: Any,
        block_addr: int,
        block: Any,
        exclusion_zones: list[Any],
    ) -> list[dict[str, Any]]:
        opportunities: list[dict[str, Any]] = []

        if not hasattr(block, "instructions"):
            return opportunities

        for i, insn in enumerate(block.instructions):
            insn_addr = insn.get("offset", insn.get("addr", 0))

            if self.should_avoid_pattern(insn_addr):
                continue

            in_zone = any(zone.contains(insn_addr) for zone in exclusion_zones)
            if in_zone:
                continue

            if random.random() < self.density:
                opportunities.append(
                    {
                        "type": "opaque_predicate",
                        "address": f"0x{insn_addr:x}",
                        "position": i,
                    }
                )

        return opportunities


def create_hardened_opaque_pass(**kwargs: Any) -> HardenedOpaquePredicates:
    return HardenedOpaquePredicates(**kwargs)


__all__ = ["HardenedOpaquePredicates", "create_hardened_opaque_pass"]
