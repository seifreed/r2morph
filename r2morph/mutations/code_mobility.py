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

import logging
import random
from dataclasses import dataclass, field
from typing import Any

from r2morph.core.binary import Binary
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
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

    def add_block(self, block: MobileBlock):
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

    def _get_basic_blocks(self, binary: Binary, func_addr: int) -> list[dict[str, Any]]:
        """Get basic blocks for a function."""
        try:
            return binary.get_basic_blocks(func_addr)
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

    def _create_mobility_plan(self, binary: Binary, functions: list[dict[str, Any]]) -> MobilityPlan:
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
            f"",
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

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply code mobility transformation.

        Args:
            binary: Binary to transform

        Returns:
            Statistics dictionary

        NOTE: This is a PLACEHOLDER. Full implementation requires:
        - Allocating new sections in the binary
        - Copying code blocks to new sections
        - Patching jump targets at original locations
        - Updating relocations and references
        """
        self._reset_random()
        logger.info("Applying code mobility")
        logger.warning(
            "Code mobility PLACEHOLDER: analyzing code but NOT modifying binary. "
            "Full implementation needed for actual mobility."
        )

        functions = binary.get_functions()
        plan = self._create_mobility_plan(binary, functions)

        if not plan.blocks:
            logger.info("No blocks selected for mobility")
            return {
                "blocks_moved": 0,
                "sections_created": 0,
                "avg_block_size": 0,
                "placeholder": True,
            }

        interleaved_blocks = self._interleave_blocks(plan.blocks)

        total_size = sum(b.size for b in interleaved_blocks)
        sections_used = set(b.target_section for b in interleaved_blocks)

        section_asm = {}
        for section_name in sorted(sections_used):
            section_idx = int(section_name.split("_")[-1])
            section_asm[section_name] = self._generate_section_header(section_name, section_idx)

        for block in interleaved_blocks:
            if block.target_section not in section_asm:
                continue

            block_code = self._generate_block_code(block, block.original_section)
            section_asm[block.target_section] += block_code

        for section_name, asm in section_asm.items():
            logger.debug(f"Generated {section_name}: {len(asm)} bytes of assembly")

        if self._session is not None:
            mutation_checkpoint = self._create_mutation_checkpoint("code_mobility")
        else:
            mutation_checkpoint = None

        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, 0)

        self._record_mutation(
            function_address=None,
            start_address=0,
            end_address=0,
            original_bytes=b"",
            mutated_bytes=b"",
            original_disasm="code_sections",
            mutated_disasm=f"mobility_plan (placeholder - {len(interleaved_blocks)} blocks planned)",
            mutation_kind="code_mobility",
            metadata={
                "blocks_moved": len(interleaved_blocks),
                "sections_created": len(sections_used),
                "avg_block_size": total_size // max(len(interleaved_blocks), 1),
                "placeholder": True,
                "structural_baseline": baseline,
            },
        )

        return {
            "blocks_moved": len(interleaved_blocks),
            "sections_created": len(sections_used),
            "avg_block_size": total_size // max(len(interleaved_blocks), 1),
            "section_names": list(sections_used),
            "preserve_order": self.preserve_order,
            "placeholder": True,
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
