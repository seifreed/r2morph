"""Dataclasses and pure helpers for code mobility."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MobileBlock:
    """A block of code that can be moved."""

    block_id: int
    original_address: int
    original_section: str
    size: int
    instructions: list[dict[str, Any]] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    target_section: str = ""

    def get_jump_size(self) -> int:
        """Estimate jump instruction size for relocation."""
        return 5


@dataclass
class MobilityPlan:
    """Plan for moving blocks between sections."""

    blocks: list[MobileBlock] = field(default_factory=list)
    section_layout: dict[str, list[int]] = field(default_factory=dict)
    entry_points: dict[int, int] = field(default_factory=dict)

    def add_block(self, block: MobileBlock) -> None:
        """Add a block to the plan."""
        self.blocks.append(block)
        if block.target_section not in self.section_layout:
            self.section_layout[block.target_section] = []
        self.section_layout[block.target_section].append(block.block_id)


def calculate_section_offsets(
    sections: list[str], base_addr: int = 0x100000, alignment: int = 0x1000
) -> dict[str, int]:
    """Calculate offsets for mobile sections."""
    offsets = {}
    current_addr = base_addr

    for section in sections:
        current_addr = (current_addr + alignment - 1) & ~(alignment - 1)
        offsets[section] = current_addr
        current_addr += 0x10000

    return offsets


def estimate_size_with_jumps(blocks: list[MobileBlock]) -> int:
    """Estimate total size including jump overhead."""
    base_size = sum(b.size for b in blocks)
    jump_overhead = len(blocks) * 5
    return base_size + jump_overhead


__all__ = [
    "MobileBlock",
    "MobilityPlan",
    "calculate_section_offsets",
    "estimate_size_with_jumps",
]
