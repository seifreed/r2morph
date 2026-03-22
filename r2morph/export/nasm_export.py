"""
NASM Export Module for r2morph.

Generates NASM-compatible assembly output from mutated code.

Features:
- Generate NASM-compatible .asm files from basic blocks
- Shuffle basic blocks while keeping entry point first
- Remove redundant fall-through jumps
- Assemble to binary using NASM
- Support for position-independent code (PIC)
"""

import logging
import os
import random
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class Instruction:
    """Instruction representation for NASM export."""

    address: int = 0
    mnemonic: str = ""
    operand_1: str = ""
    operand_2: str = ""
    operand_3: str = ""
    opcode: str = ""
    bytes_hex: str = ""
    ins_type: str = ""
    jump_target: int | None = None
    mutated: bool = False
    comment: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Instruction":
        """Create Instruction from dictionary."""
        return cls(
            address=data.get("addr", data.get("address", 0)),
            mnemonic=data.get("mnemonic", ""),
            operand_1=data.get("operand_1", data.get("op1", "")),
            operand_2=data.get("operand_2", data.get("op2", "")),
            operand_3=data.get("operand_3", data.get("op3", "")),
            opcode=data.get("opcode", data.get("disasm", "")),
            bytes_hex=data.get("bytes", ""),
            ins_type=data.get("type", ""),
            jump_target=data.get("jump", None),
            mutated=data.get("mutated", False),
            comment=data.get("comment", ""),
        )


@dataclass
class BasicBlock:
    """Basic block representation for NASM export."""

    address: int = 0
    label: str = ""
    instructions: list[Instruction] = field(default_factory=list)
    jump: int | None = None
    fail: int | None = None
    asm: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BasicBlock":
        """Create BasicBlock from dictionary."""
        bb = cls(
            address=data.get("addr", 0),
            label=data.get("label", f"block_{hex(data.get('addr', 0))}"),
            jump=data.get("jump", None),
            fail=data.get("fail", None),
        )
        ops = data.get("ops", data.get("instructions", []))
        for op in ops:
            if isinstance(op, dict):
                bb.instructions.append(Instruction.from_dict(op))
            elif isinstance(op, Instruction):
                bb.instructions.append(op)
        return bb


def generate_block_asm(block: BasicBlock, labels: dict[int, str]) -> str:
    """
    Generate NASM-compatible assembly for a basic block.

    If instruction is mutated and has opcode defined, uses that opcode.
    Otherwise hardcodes instruction bytes using 'db'.

    Args:
        block: BasicBlock to convert to assembly
        labels: Dictionary mapping addresses to labels

    Returns:
        Assembly string for the block
    """
    lines = []

    block_label = block.label if block.label else f"block_{hex(block.address)}"
    lines.append(f"{block_label}:")

    for ins in block.instructions:
        if ins.mutated and ins.opcode:
            opcode = ins.opcode
            if ins.jump_target is not None and ins.jump_target in labels:
                target_label = labels[ins.jump_target]
                opcode = _replace_target_with_label(opcode, ins.jump_target, target_label)
            lines.append(f"    {opcode}")
            if ins.comment:
                lines[-1] += f"  ; {ins.comment}"
        else:
            raw_bytes = ins.bytes_hex
            if raw_bytes:
                clean_bytes = raw_bytes.replace(" ", "").replace("\\x", "")
                byte_list = [clean_bytes[i : i + 2] for i in range(0, len(clean_bytes), 2)]
                db_line = "    db " + ", ".join(f"0x{b}" for b in byte_list)
                if ins.opcode and not ins.mutated:
                    db_line += f"  ; {ins.opcode}"
                lines.append(db_line)

    return "\n".join(lines)


def _replace_target_with_label(opcode: str, target: int, label: str) -> str:
    """Replace numeric target address with symbolic label in opcode."""
    target_hex = hex(target)
    opcode = opcode.replace(target_hex, label)
    target_hex_upper = "0X" + target_hex[2:]
    opcode = opcode.replace(target_hex_upper, label)
    target_dec = str(target)
    opcode = opcode.replace(target_dec, label)
    return opcode


def shuffle_blocks(blocks: list[BasicBlock]) -> list[BasicBlock]:
    """
    Shuffle basic blocks randomly while keeping the first block fixed.

    The entry point (first block) must always remain first.
    All other blocks are shuffled randomly.

    Args:
        blocks: List of BasicBlock objects

    Returns:
        Shuffled list with first block fixed
    """
    if len(blocks) <= 1:
        return blocks

    first_block = blocks[0]
    other_blocks = blocks[1:]
    random.shuffle(other_blocks)

    return [first_block] + other_blocks


def remove_redundant_fallthrough(blocks: list[BasicBlock], labels: dict[int, str]) -> list[BasicBlock]:
    """
    Remove redundant fall-through jmp instructions.

    Checks if the last instruction of a block is a jmp to the immediate
    following block. If so, removes the redundant jmp.

    Args:
        blocks: List of BasicBlock objects
        labels: Dictionary mapping addresses to labels

    Returns:
        Blocks with redundant jumps removed
    """
    if len(blocks) <= 1:
        return blocks

    for i in range(len(blocks) - 1):
        block = blocks[i]
        next_block = blocks[i + 1]

        if not block.instructions:
            continue

        last_ins = block.instructions[-1]
        expected_label = next_block.label if next_block.label else f"block_{hex(next_block.address)}"
        expected_addr = next_block.address

        if last_ins.mnemonic == "jmp":
            target = last_ins.jump_target
            if target == expected_addr or (target and target in labels and labels[target] == expected_label):
                block.instructions = block.instructions[:-1]
                logger.debug(f"Removed redundant fallthrough jmp at block {block.label}")

    return blocks


def generate_final_asm(
    blocks: list[BasicBlock],
    labels: dict[int, str],
    base_address: int = 0x1000,
    entry_label: str = "_start",
    architecture: str = "x86",
    bits: int = 64,
    include_comments: bool = True,
) -> str:
    """
    Generate complete NASM-compatible assembly file.

    Args:
        blocks: List of BasicBlock objects
        labels: Dictionary mapping addresses to labels
        base_address: Virtual base address for the code
        entry_label: Entry point label name
        architecture: Target architecture (x86, arm)
        bits: Bit width (32, 64)
        include_comments: Whether to include comments

    Returns:
        Complete NASM assembly string
    """
    lines = []

    if architecture == "x86":
        lines.append(f"BITS {bits}")
    lines.append("default rel")
    lines.append(f"global {entry_label}")
    lines.append("section .text")
    lines.append(f"{entry_label}:")
    lines.append("")

    for block in blocks:
        block_asm = generate_block_asm(block, labels)
        if include_comments:
            lines.append(f"; Block at original address: 0x{block.address:x}")
        lines.append(block_asm)
        lines.append("")

    return "\n".join(lines)


def assemble_nasm(
    asm_code: str,
    output_path: str,
    save_asm: bool = False,
    nasm_path: str = "nasm",
) -> tuple[bool, str, Optional[str]]:
    """
    Assemble NASM code using the NASM assembler.

    Args:
        asm_code: Assembly code string
        output_path: Path for output binary file
        save_asm: If True, save the .asm file alongside the binary
        nasm_path: Path to NASM executable

    Returns:
        Tuple of (success, message, asm_file_path)
    """
    asm_file_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".asm",
            dir="." if save_asm else None,
            delete=not save_asm,
            prefix="r2morph_",
        ) as asm_file:
            asm_file.write(asm_code)
            asm_file.flush()
            asm_file_path = asm_file.name

            if save_asm:
                saved_path = os.path.join(os.getcwd(), os.path.basename(asm_file.name))
                logger.info(f"ASM file saved at: {saved_path}")

            result = subprocess.run(
                [nasm_path, "-f", "bin", asm_file.name, "-o", output_path],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return False, f"NASM assembly failed: {result.stderr}", asm_file_path

            return True, f"Successfully assembled to {output_path}", asm_file_path

    except subprocess.SubprocessError as e:
        return False, f"NASM subprocess error: {e}", asm_file_path
    except FileNotFoundError:
        return False, f"NASM not found at path: {nasm_path}. Please install NASM.", asm_file_path
    except Exception as e:
        return False, f"Unexpected error during assembly: {e}", asm_file_path


class NASMExporter:
    """
    High-level NASM exporter for mutated shellcode.

    Provides a convenient interface for:
    - Converting r2 BasicBlocks to NASM assembly
    - Shuffling and reordering blocks
    - Generating position-independent code
    - Assembling to binary
    """

    def __init__(
        self,
        base_address: int = 0x1000,
        architecture: str = "x86",
        bits: int = 64,
        entry_label: str = "_start",
    ):
        self.base_address = base_address
        self.architecture = architecture
        self.bits = bits
        self.entry_label = entry_label
        self.blocks: list[BasicBlock] = []
        self.labels: dict[int, str] = {}

    def add_block(self, block: BasicBlock) -> None:
        """Add a basic block to the exporter."""
        self.blocks.append(block)
        label = block.label if block.label else f"block_{hex(block.address)}"
        self.labels[block.address] = label

    def add_block_from_dict(self, block_dict: dict[str, Any]) -> None:
        """Add a basic block from dictionary format."""
        block = BasicBlock.from_dict(block_dict)
        self.add_block(block)

    def set_blocks(self, blocks: list[BasicBlock]) -> None:
        """Set all blocks at once."""
        self.blocks = blocks
        for block in blocks:
            label = block.label if block.label else f"block_{hex(block.address)}"
            self.labels[block.address] = label

    def set_labels(self, labels: dict[int, str]) -> None:
        """Set custom labels for addresses."""
        self.labels.update(labels)

    def patch_control_flow(self) -> None:
        """Patch control flow instructions to use symbolic labels."""
        for block in self.blocks:
            for ins in block.instructions:
                if ins.ins_type in ("jmp", "cjmp", "call"):
                    if ins.jump_target is not None and ins.jump_target in self.labels:
                        target_label = self.labels[ins.jump_target]
                        ins.opcode = f"{ins.mnemonic} {target_label}"
                        ins.mutated = True

    def do_shuffle_blocks(self) -> None:
        """Shuffle blocks while keeping entry point first."""
        self.blocks = shuffle_blocks(self.blocks)

    def do_remove_redundant_jumps(self) -> None:
        """Remove redundant fall-through jumps."""
        self.blocks = remove_redundant_fallthrough(self.blocks, self.labels)

    def generate_asm(self, include_comments: bool = True) -> str:
        """Generate complete NASM assembly."""
        return generate_final_asm(
            self.blocks,
            self.labels,
            self.base_address,
            self.entry_label,
            self.architecture,
            self.bits,
            include_comments,
        )

    def assemble(self, output_path: str, save_asm: bool = False) -> tuple[bool, str]:
        """Assemble to binary using NASM."""
        asm_code = self.generate_asm()
        success, message, _ = assemble_nasm(asm_code, output_path, save_asm)
        return success, message

    def export(
        self,
        output_path: str,
        shuffle: bool = False,
        remove_redundant: bool = True,
        save_asm: bool = False,
    ) -> tuple[bool, str, str]:
        """
        Full export pipeline.

        Args:
            output_path: Path for output binary
            shuffle: Whether to shuffle blocks
            remove_redundant: Whether to remove redundant jumps
            save_asm: Whether to save .asm file

        Returns:
            Tuple of (success, message, asm_code)
        """
        self.patch_control_flow()

        if shuffle:
            self.do_shuffle_blocks()

        if remove_redundant:
            self.do_remove_redundant_jumps()

        asm_code = self.generate_asm()
        success, message = self.assemble(output_path, save_asm)

        return success, message, asm_code


def export_shellcode(
    blocks: list[dict[str, Any]],
    output_path: str,
    base_address: int = 0x1000,
    shuffle: bool = False,
    save_asm: bool = False,
    verbose: bool = False,
) -> tuple[bool, str, Optional[str]]:
    """
    Convenience function to export shellcode to NASM.

    Args:
        blocks: List of basic block dictionaries
        output_path: Path for output binary
        base_address: Virtual base address
        shuffle: Whether to shuffle blocks
        save_asm: Whether to save .asm file
        verbose: Print verbose output

    Returns:
        Tuple of (success, message, asm_code_or_none)
    """
    exporter = NASMExporter(base_address=base_address)

    for block_dict in blocks:
        exporter.add_block_from_dict(block_dict)

    success, message, asm_code = exporter.export(
        output_path=output_path,
        shuffle=shuffle,
        save_asm=save_asm,
    )

    if verbose:
        logger.info(f"Export result: {message}")
        if save_asm and asm_code:
            logger.info(f"Generated {len(asm_code.split(chr(10)))} lines of assembly")

    return success, message, asm_code
