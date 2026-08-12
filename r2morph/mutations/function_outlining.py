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

Implementation uses CaveFinder to locate executable code caves,
relocates non-entry chunks with trampoline jumps at original sites.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import r2morph.core.randomness as random
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.base import MutationPass
from r2morph.relocations.cave_finder import CaveFinder, CodeCave

logger = logging.getLogger(__name__)

_MIN_OUTLINE_BLOCKS = 2
_RELATIVE_JUMP_SIZE_BYTES = 5
_SIGNED_32_MIN = -(1 << 31)
_SIGNED_32_MAX = (1 << 31) - 1


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
        if len(blocks) < _MIN_OUTLINE_BLOCKS:
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
            disasm_ok = True

            for block in chunk_blocks:
                try:
                    insns = binary.r2.cmdj(f"pdj {block.get('size', 0)} @ {block.get('addr', 0)}") or []
                except (ValueError, OSError, RuntimeError) as exc:
                    logger.warning(
                        "Disassembly failed for block at 0x%x while outlining; "
                        "skipping this chunk to avoid emitting truncated code: %s",
                        block.get("addr", 0),
                        exc,
                    )
                    disasm_ok = False
                    break
                instructions.extend(insns)

            # Advance the cursor regardless so chunk boundaries stay
            # consistent even when a chunk is skipped.
            current_idx = end_idx

            if not disasm_ok:
                # Emitting a chunk whose body is missing instructions would
                # corrupt control flow in the rewritten binary. Skip it.
                chunk_id += 1
                continue

            jump_target = None
            fallthrough_target = None

            if chunk_blocks:
                last_block = chunk_blocks[-1]
                jump_target = last_block.get("jump", None)
                fail = last_block.get("fail", None)

                if fail:
                    fallthrough_target = fail

            chunk = OutlinedChunk(
                chunk_id=chunk_id,
                original_address=start_addr,
                instructions=instructions,
                jump_target=jump_target,
                fallthrough_target=fallthrough_target,
            )
            chunks.append(chunk)

            chunk_id += 1

        return chunks

    @staticmethod
    def _chunk_bytes(binary: Any, chunk: OutlinedChunk) -> tuple[int, int, str, bytes] | None:
        if not chunk.instructions:
            return None
        first_address = int(chunk.instructions[0].get("offset", chunk.original_address))
        last_instruction = chunk.instructions[-1]
        last_address = int(last_instruction.get("offset", first_address))
        chunk_size = last_address + int(last_instruction.get("size", 1)) - first_address
        disasm = "; ".join(str(instruction.get("disasm", "")) for instruction in chunk.instructions[:3])
        if chunk_size < _RELATIVE_JUMP_SIZE_BYTES or "[rip" in disasm:
            return None
        original_bytes = binary.read_bytes(first_address, chunk_size)
        if not original_bytes or len(original_bytes) < _RELATIVE_JUMP_SIZE_BYTES:
            return None
        return first_address, chunk_size, disasm, bytes(original_bytes)

    @staticmethod
    def _allocate_cave(caves: list[CodeCave], cave_index: int, size: int) -> tuple[int | None, int]:
        while cave_index < len(caves):
            cave = caves[cave_index]
            if cave.size >= size:
                caves[cave_index] = CodeCave(
                    address=cave.address + size,
                    size=cave.size - size,
                    section=cave.section,
                    is_executable=cave.is_executable,
                )
                return cave.address, cave_index
            cave_index += 1
        return None, cave_index

    @staticmethod
    def _relative_jump(target: int, next_instruction: int) -> bytes | None:
        offset = target - next_instruction
        if not _SIGNED_32_MIN <= offset <= _SIGNED_32_MAX:
            return None
        return b"\xe9" + offset.to_bytes(4, "little", signed=True)

    def _relocate_chunk(
        self,
        binary: Any,
        function_address: int,
        chunk: OutlinedChunk,
        caves: list[CodeCave],
        cave_index: int,
    ) -> tuple[bool, int]:
        chunk_data = self._chunk_bytes(binary, chunk)
        if chunk_data is None:
            return False, cave_index
        first_address, chunk_size, disasm, original_bytes = chunk_data
        needed = chunk_size + _RELATIVE_JUMP_SIZE_BYTES
        cave_address, cave_index = self._allocate_cave(caves, cave_index, needed)
        if cave_address is None:
            return False, cave_index
        return_jump = self._relative_jump(first_address + chunk_size, cave_address + needed)
        if return_jump is None:
            logger.debug(f"Return offset out of range for chunk at 0x{first_address:x}")
        if return_jump is None or not binary.write_bytes(cave_address, original_bytes + return_jump):
            return False, cave_index
        trampoline = self._relative_jump(cave_address, first_address + _RELATIVE_JUMP_SIZE_BYTES)
        if trampoline is None:
            logger.debug(f"Trampoline offset out of range for chunk at 0x{first_address:x}")
            return False, cave_index
        rewritten = trampoline + b"\x90" * (chunk_size - _RELATIVE_JUMP_SIZE_BYTES)
        if not binary.write_bytes(first_address, rewritten):
            logger.warning("Trampoline write failed at 0x%x; chunk not outlined, skipping record", first_address)
            return False, cave_index
        self._record_mutation(
            function_address=function_address,
            start_address=first_address,
            end_address=first_address + chunk_size,
            original_bytes=original_bytes,
            mutated_bytes=rewritten,
            original_disasm=disasm,
            mutated_disasm=f"jmp 0x{cave_address:x} (outlined chunk)",
            mutation_kind="function_outlining",
        )
        return True, cave_index

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply function outlining.

        Relocates non-entry chunks of selected functions to code caves,
        replacing the original chunk location with a trampoline jump.
        """
        self._reset_random()
        logger.info("Applying function outlining")

        functions = binary.get_functions()
        outlined_functions: list[OutlinedFunction] = []
        total_chunks = 0
        total_blocks = 0
        chunks_relocated = 0

        caves = CaveFinder(binary).find_caves()
        cave_idx = 0

        if self._session is not None:
            self._create_mutation_checkpoint("function_outlining")

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
            if len(chunks) < _MIN_OUTLINE_BLOCKS:
                continue

            outlined_func = OutlinedFunction(
                original_address=func_addr,
                original_name=func_name,
                chunks=chunks,
                entry_chunk=chunks[0].chunk_id if chunks else 0,
            )

            for chunk in chunks[1:]:
                relocated, cave_idx = self._relocate_chunk(binary, func_addr, chunk, caves, cave_idx)
                chunks_relocated += int(relocated)

            outlined_functions.append(outlined_func)
            total_chunks += len(chunks)
            total_blocks += len(blocks)
            logger.debug(f"Outlined {func_name}: {len(blocks)} blocks -> {len(chunks)} chunks")

        return {
            "functions_outlined": len(outlined_functions),
            "chunks_relocated": chunks_relocated,
            "total_chunks": total_chunks,
            "total_blocks": total_blocks,
            "average_chunks_per_function": total_chunks / max(len(outlined_functions), 1),
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
