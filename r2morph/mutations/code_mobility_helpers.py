"""Pure helper functions for code mobility generation."""

from __future__ import annotations

import random
from typing import Any

from r2morph.mutations.code_mobility_models import MobileBlock


def can_move_block(block: dict[str, Any]) -> tuple[bool, str]:
    """Check if a block can be safely moved."""
    if block.get("size", 0) < 1:
        return False, "block too small"

    block_type = block.get("type", "")
    if block_type in ("data", "invalid"):
        return False, f"invalid block type: {block_type}"

    return True, ""


def select_target_section(block_id: int, num_sections: int, section_prefix: str) -> str:
    """Select target section for a block."""
    section_idx = block_id % num_sections
    return f"{section_prefix}_{section_idx}"


def generate_trampoline(target_addr: int, section_name: str) -> str:
    """Generate trampoline code to jump to mobile section."""
    return f"""
; Trampoline to {section_name}
jmp_mobile_{target_addr:08x}:
    jmp target_{target_addr:08x}
"""


def generate_section_header(section_name: str, section_idx: int) -> str:
    """Generate section header assembly."""
    return f"""
; ========================================
; Mobile section {section_idx}: {section_name}
; Contains relocated code blocks
; ========================================
section {section_name} align=16
{section_name}_start:
"""


def generate_block_code(block: MobileBlock, original_section: str) -> str:
    """Generate assembly for a mobile block."""
    lines = [
        "",
        f"block_{block.block_id:04x}:",
        f"    ; Original: 0x{block.original_address:08x} in {original_section}",
        f"    ; Size: {block.size} bytes",
    ]

    for succ_addr in block.successors:
        lines.append(f"    jmp block_{succ_addr:04x}  ; successor")

    lines.append(f"    ; End block_{block.block_id:04x}")
    lines.append("")

    return "\n".join(lines)


def interleave_blocks(
    blocks: list[MobileBlock],
    *,
    preserve_order: bool,
    seed: int | None = None,
) -> list[MobileBlock]:
    """Interleave blocks from different functions."""
    if seed is not None:
        random.seed(seed)

    if preserve_order:
        return blocks

    shuffled = blocks.copy()
    random.shuffle(shuffled)
    return shuffled


__all__ = [
    "can_move_block",
    "generate_block_code",
    "generate_section_header",
    "generate_trampoline",
    "interleave_blocks",
    "select_target_section",
]
