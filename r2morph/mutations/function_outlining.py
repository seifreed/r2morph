"""
Function Outlining - Split functions into distributed chunks.

Breaks function continuity by splitting basic blocks and
distributing them across different sections of the binary,
making analysis harder by obscuring control flow.

Example transformation:

    Original (contiguous in .text):
        func_A:
            mov eax, 1      ; block 1
            add eax, 2
            jmp block_2

            ret             ; block 3

        func_B:
            mov ebx, 3      ; block 4
            ...

    Outlined (distributed):
        .text:
            jmp chunk_A1    ; func A starts with jump

        .text_outlined:
        chunk_A1:
            mov eax, 1      ; out of order
            add eax, 2
            jmp chunk_A2

        .text:
        chunk_A2:
            ret             ; different location

        .text_outlined:
        chunk_B1:
            mov ebx, 3      ; interleaved

Benefits:
    - Breaks linear analysis assumptions
    - Obscures function boundaries
    - Makes disassembly harder
    - Increases complexity of CFG reconstruction

NOTE: This is a PLACEHOLDER implementation. The apply() method currently
only plans the outlining but does NOT modify the binary. Full implementation
requires:
1. Allocating space for outlined chunks
2. Writing moved blocks to new locations
3. Patching jump targets in original locations
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
class OutlinedChunk:
    """A chunk of outlined code."""

    chunk_id: int
    original_address: int
    instructions: list[dict[str, Any]]
    jump_target: int | None = None
    fallthrough_target: int | None = None
    section: str = ""

    def to_asm(self) -> str:
        """Convert chunk to assembly string."""
        lines = [f"chunk_{self.chunk_id:04x}:"]
        for insn in self.instructions:
            disasm = insn.get("disasm", insn.get("opcode", ""))
            lines.append(f"    {disasm}")
        if self.jump_target:
            lines.append(f"    jmp chunk_{self.jump_target:04x}")
        return "\n".join(lines)


@dataclass
class OutlinedFunction:
    """A function that has been outlined."""

    original_address: int
    original_name: str
    chunks: list[OutlinedChunk] = field(default_factory=list)
    entry_chunk: int = 0

    def add_chunk(self, chunk: OutlinedChunk) -> None:
        """Add a chunk to the function."""
        self.chunks.append(chunk)

    def get_chunk_order(self) -> list[int]:
        """Get chunk execution order for reconstruction."""
        order = []
        visited: set[int] = set()
        current: int | None = self.entry_chunk

        while current is not None and current not in visited:
            visited.add(current)
            order.append(current)

            chunk = next((c for c in self.chunks if c.chunk_id == current), None)
            if chunk:
                current = chunk.jump_target if chunk.jump_target else chunk.fallthrough_target
            else:
                break

        return order


class FunctionOutliningPass(MutationPass):
    """
    Mutation pass that outlines functions into distributed chunks.

    Splits functions into smaller chunks and distributes them across
    different sections, breaking continuity and complicating analysis.

    Config options:
        - probability: Probability of outlining each function (default: 0.3)
        - max_functions: Maximum functions to outline (default: 10)
        - min_chunks: Minimum chunks per function (default: 2)
        - max_chunks: Maximum chunks per function (default: 8)
        - section_name: Name for new section (default: ".outlined")
        - interleave_functions: Whether to interleave chunks from different functions (default: True)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="FunctionOutlining", config=config)
        self.probability = self.config.get("probability", 0.3)
        self.max_functions = self.config.get("max_functions", 10)
        self.min_chunks = self.config.get("min_chunks", 2)
        self.max_chunks = self.config.get("max_chunks", 8)
        self.section_name = self.config.get("section_name", ".outlined")
        self.interleave_functions = self.config.get("interleave_functions", True)
        self.set_support(
            formats=("ELF", "PE", "Mach-O"),
            architectures=("x86_64", "x86", "arm64"),
            validators=("structural",),
            stability="experimental",
            notes=(
                "splits functions into distributed chunks",
                "creates new section for outlined code",
                "can interleave chunks from different functions",
            ),
        )

    def _get_basic_blocks(self, binary: Any, func_addr: int) -> list[dict[str, Any]]:
        """Get basic blocks for a function."""
        try:
            blocks = binary.get_basic_blocks(func_addr)
            return list(blocks)
        except Exception as e:
            logger.debug(f"Failed to get blocks at 0x{func_addr:x}: {e}")
            return []

    def _can_outline(self, blocks: list[dict[str, Any]]) -> tuple[bool, str]:
        """Check if function can be outlined."""
        if len(blocks) < 2:
            return False, "insufficient blocks"

        for block in blocks:
            size = block.get("size", 0)
            if size < 1:
                return False, "block too small"

        return True, ""

    def _split_into_chunks(
        self, blocks: list[dict[str, Any]], binary: Any, min_chunks: int, max_chunks: int
    ) -> list[OutlinedChunk]:
        """Split blocks into chunks for outlining."""
        if len(blocks) < min_chunks:
            min_chunks = 1
            max_chunks = len(blocks)

        num_chunks = random.randint(min_chunks, min(max_chunks, len(blocks)))
        chunk_size = max(1, len(blocks) // num_chunks)

        chunks = []
        chunk_id = random.randint(0x1000, 0xFFFF)
        current_idx = 0

        for i in range(num_chunks):
            end_idx = min(current_idx + chunk_size, len(blocks))
            if i == num_chunks - 1:
                end_idx = len(blocks)

            chunk_blocks = blocks[current_idx:end_idx]
            if not chunk_blocks:
                continue

            start_addr = chunk_blocks[0].get("addr", 0)
            instructions: list[dict[str, Any]] = []

            for block in chunk_blocks:
                try:
                    insns = binary.r2.cmdj(f"pdj {block.get('size', 0)} @ {block.get('addr', 0)}") or []
                    instructions.extend(insns)
                except Exception:
                    pass

            jump_target = None
            fallthrough_target = None

            if len(chunk_blocks) > 0:
                last_block = chunk_blocks[-1]
                jump_target = last_block.get("jump", None)
                fail = last_block.get("fail", None)

                if fail:
                    fallthrough_target = fail
                elif jump_target:
                    jump_target = jump_target

            chunk = OutlinedChunk(
                chunk_id=chunk_id,
                original_address=start_addr,
                instructions=instructions,
                jump_target=jump_target,
                fallthrough_target=fallthrough_target,
            )
            chunks.append(chunk)

            chunk_id += 1
            current_idx = end_idx

        return chunks

    def _generate_outline_asm(self, chunks: list[OutlinedChunk], interleave: bool = True) -> tuple[str, dict[int, int]]:
        """
        Generate assembly for outlined chunks.

        Returns:
            Tuple of (assembly code, chunk_id to offset mapping)
        """
        asm_lines = [f"; Outlined function chunks ({len(chunks)} total)", ""]

        if interleave:
            chunk_order = list(enumerate(chunks))
            random.shuffle(chunk_order)
        else:
            chunk_order = list(enumerate(chunks))

        chunk_offsets: dict[int, int] = {}

        for idx, (original_idx, chunk) in enumerate(chunk_order):
            for insn in chunk.instructions:
                disasm = insn.get("disasm", insn.get("opcode", ""))
                if insn.get("type") == "jmp" and insn.get("jump"):
                    target = insn.get("jump")
                    asm_lines.append(f"    jmp target_{target:04x}  ; redirected")
                elif insn.get("type") in ("cjmp", "call"):
                    asm_lines.append(f"    {disasm}  ; control flow")
                else:
                    asm_lines.append(f"    {disasm}")

        return "\n".join(asm_lines), chunk_offsets

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply function outlining.

        Args:
            binary: Any to outline

        Returns:
            Statistics dictionary

        NOTE: This is a PLACEHOLDER. Full implementation requires:
        - Allocating space for outlined chunks
        - Writing moved blocks to new locations
        - Patching jump targets in original locations
        - Updating relocations and references
        """
        self._reset_random()
        logger.info("Applying function outlining")
        logger.warning(
            "Function outlining PLACEHOLDER: analyzing functions but NOT modifying binary. "
            "Full implementation needed for actual outlining."
        )

        functions = binary.get_functions()
        outlined_functions: list[OutlinedFunction] = []
        total_chunks = 0
        total_blocks = 0

        for func in functions:
            if len(outlined_functions) >= self.max_functions:
                break

            func_addr = func.get("addr", 0)
            func_name = func.get("name", f"func_{func_addr:x}")

            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            if random.random() > self.probability:
                continue

            blocks = self._get_basic_blocks(binary, func_addr)
            if not blocks:
                continue

            can_outline, reason = self._can_outline(blocks)
            if not can_outline:
                logger.debug(f"Cannot outline {func_name}: {reason}")
                continue

            chunks = self._split_into_chunks(blocks, binary, self.min_chunks, self.max_chunks)

            if len(chunks) < 2:
                continue

            outlined_func = OutlinedFunction(
                original_address=func_addr,
                original_name=func_name,
                chunks=chunks,
                entry_chunk=chunks[0].chunk_id if chunks else 0,
            )

            outline_asm, chunk_offsets = self._generate_outline_asm(chunks, self.interleave_functions)

            outlined_functions.append(outlined_func)
            total_chunks += len(chunks)
            total_blocks += len(blocks)

            logger.debug(f"Outlined {func_name}: {len(blocks)} blocks -> {len(chunks)} chunks")

        if self._session is not None:
            self._create_mutation_checkpoint("function_outlining")
        else:
            pass

        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, 0)

        self._record_mutation(
            function_address=None,
            start_address=0,
            end_address=0,
            original_bytes=b"",
            mutated_bytes=b"",
            original_disasm="functions",
            mutated_disasm=f"function_outlining (placeholder - {len(outlined_functions)} functions outlined)",
            mutation_kind="function_outlining",
            metadata={
                "functions_outlined": len(outlined_functions),
                "total_chunks": total_chunks,
                "total_blocks": total_blocks,
                "average_chunks_per_function": total_chunks / max(len(outlined_functions), 1),
                "interleaved": self.interleave_functions,
                "section_name": self.section_name,
                "placeholder": True,
                "structural_baseline": baseline,
            },
        )

        return {
            "functions_outlined": len(outlined_functions),
            "total_chunks": total_chunks,
            "total_blocks": total_blocks,
            "average_chunks_per_function": total_chunks / max(len(outlined_functions), 1),
            "interleaved": self.interleave_functions,
            "section_name": self.section_name,
            "placeholder": True,
        }


def calculate_chunk_layout(all_chunks: list[OutlinedChunk], alignment: int = 16) -> dict[int, int]:
    """
    Calculate layout positions for chunks.

    Args:
        all_chunks: All chunks to layout
        alignment: Alignment requirement for each chunk

    Returns:
        Dictionary mapping chunk_id to address
    """
    layout = {}
    current_addr = 0x10000

    sorted_chunks = sorted(all_chunks, key=lambda c: c.chunk_id)

    for chunk in sorted_chunks:
        chunk_size = len(chunk.instructions) * 4

        current_addr = (current_addr + alignment - 1) & ~(alignment - 1)

        layout[chunk.chunk_id] = current_addr
        current_addr += chunk_size

    return layout


def generate_interleaved_layout(functions: list[OutlinedFunction], seed: int | None = None) -> list[OutlinedChunk]:
    """
    Generate interleaved layout for chunks from multiple functions.

    Shuffles chunks from different functions together to
    make analysis harder.

    Args:
        functions: List of outlined functions
        seed: Random seed for reproducibility

    Returns:
        Interleaved list of chunks
    """
    if seed is not None:
        random.seed(seed)

    all_chunks = []
    for func in functions:
        all_chunks.extend(func.chunks)

    random.shuffle(all_chunks)
    return all_chunks
