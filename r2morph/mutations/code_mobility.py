"""
Code Mobility - Move code between sections.

Distributes code blocks across different sections of the binary,
breaking spatial locality and making analysis harder by
scattering related code across non-contiguous regions.

Example transformation:

    Original (.text):
        func_A:
            mov eax, 1
            add eax, 2
            ret
        func_B:
            mov ebx, 3
            ret

    Mobilized:
        .text:
            jmp func_B_impl    ; func_A jumps to implementation

        .mobile_0:
        func_A_impl:
            mov eax, 1
            jmp func_A_cont

        .mobile_1:
        func_A_cont:
            add eax, 2
            ret

        .mobile_2:
        func_B_impl:
            mov ebx, 3
            ret

Benefits:
    - Breaks spatial locality assumptions in analysis
    - Makes function boundary detection harder
    - Distributes code entropy across sections
    - Complicates linear disassembly

NOTE: This is a PLACEHOLDER implementation. The apply() method currently
only plans the mobility but does NOT modify the binary. Full implementation
requires:
1. Allocating new sections in the binary
2. Copying code blocks to new sections
3. Patching jump targets at original locations
4. Updating relocations and references

TODO: Implement actual binary modification.
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

if TYPE_CHECKING:
    pass
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


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


class CodeMobilityPass(MutationPass):
    """
    Mutation pass that moves code blocks between sections.

    Distributes code across multiple sections to break spatial
    locality and complicate analysis.

    Config options:
        - probability: Probability of moving each block (default: 0.3)
        - max_blocks: Maximum blocks to move (default: 50)
        - num_sections: Number of mobile sections to create (default: 4)
        - section_prefix: Prefix for mobile section names (default: ".mobile")
        - preserve_order: Whether to preserve original order hints (default: False)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="CodeMobility", config=config)
        self.probability = self.config.get("probability", 0.3)
        self.max_blocks = self.config.get("max_blocks", 50)
        self.num_sections = self.config.get("num_sections", 4)
        self.section_prefix = self.config.get("section_prefix", ".mobile")
        self.preserve_order = self.config.get("preserve_order", False)
        self.set_support(
            formats=("ELF", "PE", "Mach-O"),
            architectures=("x86_64", "x86", "arm64"),
            validators=("structural",),
            stability="experimental",
            notes=(
                "moves code blocks to different sections",
                "creates mobile sections at end of binary",
                "updates jumps between blocks",
            ),
        )

    def _get_basic_blocks(self, binary: Any, func_addr: int) -> list[dict[str, Any]]:
        """Get basic blocks for a function."""
        try:
            return list(binary.get_basic_blocks(func_addr))
        except Exception as e:
            logger.debug(f"Failed to get blocks: {e}")
            return []

    def _can_move_block(self, block: dict[str, Any]) -> tuple[bool, str]:
        """Check if a block can be safely moved."""
        if block.get("size", 0) < 1:
            return False, "block too small"

        block_type = block.get("type", "")
        if block_type in ("data", "invalid"):
            return False, f"invalid block type: {block_type}"

        return True, ""

    def _select_target_section(self, block_id: int, num_sections: int) -> str:
        """Select target section for a block."""
        section_idx = block_id % num_sections
        return f"{self.section_prefix}_{section_idx}"

    def _create_mobility_plan(self, binary: Any, functions: list[dict[str, Any]]) -> MobilityPlan:
        """Create plan for moving blocks."""
        plan = MobilityPlan()
        block_id = 0

        for func in functions:
            func_addr = func.get("addr", 0)

            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            blocks = self._get_basic_blocks(binary, func_addr)

            for block in blocks:
                if len(plan.blocks) >= self.max_blocks:
                    break

                can_move, reason = self._can_move_block(block)
                if not can_move:
                    logger.debug(f"Cannot move block: {reason}")
                    continue

                if random.random() > self.probability:
                    continue

                target_section = self._select_target_section(block_id, self.num_sections)

                mobile_block = MobileBlock(
                    block_id=block_id,
                    original_address=block.get("addr", 0),
                    original_section=".text",
                    size=block.get("size", 0),
                    target_section=target_section,
                )

                jump_addr = block.get("jump", None)
                fail_addr = block.get("fail", None)

                if jump_addr:
                    mobile_block.successors.append(jump_addr)
                if fail_addr:
                    mobile_block.successors.append(fail_addr)

                plan.add_block(mobile_block)
                block_id += 1

        return plan

    def _generate_trampoline(self, target_addr: int, section_name: str) -> str:
        """Generate trampoline code to jump to mobile section."""
        return f"""
; Trampoline to {section_name}
jmp_mobile_{target_addr:08x}:
    jmp target_{target_addr:08x}
"""

    def _generate_section_header(self, section_name: str, section_idx: int) -> str:
        """Generate section header assembly."""
        return f"""
; ========================================
; Mobile section {section_idx}: {section_name}
; Contains relocated code blocks
; ========================================
section {section_name} align=16
{section_name}_start:
"""

    def _generate_block_code(self, block: MobileBlock, original_section: str) -> str:
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

    def _interleave_blocks(self, blocks: list[MobileBlock], seed: int | None = None) -> list[MobileBlock]:
        """Interleave blocks from different functions."""
        if seed is not None:
            random.seed(seed)

        if self.preserve_order:
            return blocks

        shuffled = blocks.copy()
        random.shuffle(shuffled)
        return shuffled

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply code mobility transformation.

        Relocates basic blocks to code caves, replacing originals with
        trampolines. Each relocated block ends with a jump back to the
        instruction following the original block.
        """
        self._reset_random()
        logger.info("Applying code mobility")

        functions = binary.get_functions()
        plan = self._create_mobility_plan(binary, functions)

        if not plan.blocks:
            logger.info("No blocks selected for mobility")
            return {"blocks_moved": 0, "sections_created": 0, "avg_block_size": 0}

        interleaved_blocks = self._interleave_blocks(plan.blocks)

        from r2morph.relocations.cave_finder import CaveFinder

        caves = CaveFinder(binary).find_caves()
        cave_idx = 0
        blocks_moved = 0

        if self._session is not None:
            self._create_mutation_checkpoint("code_mobility")

        for block in interleaved_blocks:
            if block.size < 5:
                continue

            original_bytes = binary.read_bytes(block.original_address, block.size)
            if not original_bytes or len(original_bytes) < 5:
                continue

            disasm = binary.get_function_disasm(block.original_address)
            disasm_text = "; ".join(str(i.get("disasm", "")) for i in (disasm or [])[:3])
            if "[rip" in disasm_text:
                continue

            needed = block.size + 5
            cave_addr = None
            while cave_idx < len(caves):
                c = caves[cave_idx]
                if c.size >= needed:
                    cave_addr = c.address
                    caves[cave_idx] = type(c)(
                        address=c.address + needed,
                        size=c.size - needed,
                        section=c.section,
                        is_executable=c.is_executable,
                    )
                    break
                cave_idx += 1

            if cave_addr is None:
                continue

            return_target = block.original_address + block.size
            ret_offset = return_target - (cave_addr + block.size + 5)
            return_jmp = b"\xe9" + ret_offset.to_bytes(4, "little", signed=True)

            if not binary.write_bytes(cave_addr, original_bytes + return_jmp):
                continue

            tramp_offset = cave_addr - (block.original_address + 5)
            trampoline = b"\xe9" + tramp_offset.to_bytes(4, "little", signed=True)
            nops = b"\x90" * (block.size - 5)

            binary.write_bytes(block.original_address, trampoline + nops)

            self._record_mutation(
                function_address=block.original_address,
                start_address=block.original_address,
                end_address=block.original_address + block.size,
                original_bytes=original_bytes,
                mutated_bytes=trampoline + nops,
                original_disasm=disasm_text,
                mutated_disasm=f"jmp 0x{cave_addr:x} (relocated block)",
                mutation_kind="code_mobility",
            )
            blocks_moved += 1

        total_size = sum(b.size for b in interleaved_blocks)
        return {
            "blocks_moved": blocks_moved,
            "sections_created": 0,
            "avg_block_size": total_size // max(len(interleaved_blocks), 1),
        }


def calculate_section_offsets(
    sections: list[str], base_addr: int = 0x100000, alignment: int = 0x1000
) -> dict[str, int]:
    """
    Calculate offsets for mobile sections.

    Args:
        sections: List of section names
        base_addr: Starting address
        alignment: Section alignment

    Returns:
        Dictionary mapping section name to address
    """
    offsets = {}
    current_addr = base_addr

    for section in sections:
        current_addr = (current_addr + alignment - 1) & ~(alignment - 1)
        offsets[section] = current_addr
        current_addr += 0x10000

    return offsets


def estimate_size_with_jumps(blocks: list[MobileBlock]) -> int:
    """
    Estimate total size including jump overhead.

    Args:
        blocks: List of mobile blocks

    Returns:
        Estimated size in bytes
    """
    base_size = sum(b.size for b in blocks)
    jump_overhead = len(blocks) * 5
    return base_size + jump_overhead
