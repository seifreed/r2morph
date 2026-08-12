"""
Short jump patching for control flow instructions.

Patches control flow instructions that exclusively support
short jumps to support wider jump ranges. This is necessary when injecting
generated code that may push targets beyond the ±128 byte limit.

Transformations:
- loop/loopne/loopnz -> dec rcx; jnz (for loop/loopne/loopnz)
- loope/loopz -> dec rcx; jz
- jcxz -> test cx, cx; jz
- jecxz -> test ecx, ecx; jz
- jrcxz -> test rcx, rcx; jz
"""

from __future__ import annotations

import logging
from typing import Any

import r2morph.core.randomness as random
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)

_RIP_RELATIVE_PREVIEW_COUNT = 5

SHORT_JUMP_EXCLUSIVE = {
    "loop": ("dec rcx", "jnz"),
    "loopne": ("dec rcx", "jnz"),
    "loopnz": ("dec rcx", "jnz"),
    "loope": ("dec rcx", "jz"),
    "loopz": ("dec rcx", "jz"),
    "jcxz": ("test cx, cx", "jz"),
    "jecxz": ("test ecx, ecx", "jz"),
    "jrcxz": ("test rcx, rcx", "jz"),
}


class ShortJumpPatchingPass(MutationPass):
    """
    Mutation pass that patches short-jump-exclusive instructions.

    These instructions can only jump within ±128 bytes. When code is
    injected or blocks are reordered, targets may be pushed beyond
    this limit, causing assembly errors.

    This pass converts them to two-instruction equivalents that support
    near jumps (±32KB or full address space depending on mode).
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="ShortJumpPatching", config=config)
        self.patch_probability = self.config.get("probability", 1.0)

    def _get_replacement(self, mnemonic: str) -> tuple[str, str] | None:
        """
        Get replacement instruction pair for a short-jump-exclusive mnemonic.

        Args:
            mnemonic: Original instruction mnemonic

        Returns:
            Tuple of (prefix_instruction, jump_instruction) or None
        """
        return SHORT_JUMP_EXCLUSIVE.get(mnemonic.lower())

    @staticmethod
    def _get_blocks(binary: Any, function: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            raw_blocks = binary.get_basic_blocks(function["addr"])
            return [block for block in raw_blocks if isinstance(block, dict)]
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as error:
            logger.debug(f"Failed to get blocks for {function.get('name')}: {error}")
            return []

    @staticmethod
    def _disassemble_block(binary: Any, block: dict[str, Any]) -> list[dict[str, Any]]:
        block_size = block.get("size", 0)
        if block_size < 1 or binary.r2 is None:
            return []
        try:
            raw_instructions = binary.r2.cmdj(f"pdj {block_size} @ 0x{block.get('addr', 0):x}") or []
            return [instruction for instruction in raw_instructions if isinstance(instruction, dict)]
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as error:
            logger.debug(f"Failed to disassemble block: {error}")
            return []

    def _assemble_patch(
        self, binary: Any, function_address: int, instruction: dict[str, Any]
    ) -> tuple[bytes, str, str, str] | None:
        mnemonic = instruction.get("mnemonic", "").lower()
        replacement = self._get_replacement(mnemonic)
        operand = instruction.get("jump")
        if operand is None:
            operand_text = instruction.get("opstr", "") or instruction.get("disasm", "")
            parts = operand_text.split()
            operand = parts[-1] if parts else None
        if replacement is None or operand is None:
            return None
        target = f"0x{operand:x}" if isinstance(operand, int) else operand
        prefix, jump = replacement
        assembled = binary.assemble(f"{prefix}\n{jump} {target}", function_addr=function_address)
        instruction_size = instruction.get("size", 0)
        if not assembled:
            logger.debug(f"Failed to assemble replacement at 0x{instruction.get('addr', 0):x}")
            return None
        if len(assembled) > instruction_size:
            logger.debug(
                f"Replacement too large at 0x{instruction.get('addr', 0):x}: {len(assembled)} > {instruction_size}"
            )
            return None
        return assembled, prefix, jump, target

    @staticmethod
    def _pad_patch(
        binary: Any, function_address: int, instruction_address: int, instruction_size: int, assembled: bytes
    ) -> bool:
        if len(assembled) == instruction_size:
            return True
        nop_count = instruction_size - len(assembled)
        nop_pad = binary.assemble("\n".join(["nop"] * nop_count), function_addr=function_address)
        if nop_pad and binary.write_bytes(instruction_address + len(assembled), nop_pad):
            return True
        logger.warning(
            "NOP padding failed at 0x%x (need %d bytes); rolling back short-jump patch",
            instruction_address + len(assembled),
            nop_count,
        )
        return False

    def _write_patch(
        self,
        binary: Any,
        function_address: int,
        instruction: dict[str, Any],
        patch: tuple[bytes, str, str, str],
    ) -> bool:
        assembled, prefix, jump, target = patch
        address = instruction.get("addr", 0)
        size = instruction.get("size", 0)
        original_bytes = binary.read_bytes(address, size)
        if not original_bytes:
            return False
        checkpoint = self._create_mutation_checkpoint("short_jump")
        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, function_address)
        if not binary.write_bytes(address, assembled):
            return False
        if not self._pad_patch(binary, function_address, address, size, assembled):
            self._rollback_uncommitted(
                binary,
                checkpoint,
                reason="Short-jump NOP padding failed; aborting (fail-fast)",
            )
            return False
        mnemonic = instruction.get("mnemonic", "").lower()
        mutated_bytes = binary.read_bytes(address, size)
        record = self._record_mutation(
            function_address=function_address,
            start_address=address,
            end_address=address + size - 1,
            original_bytes=original_bytes,
            mutated_bytes=mutated_bytes if mutated_bytes else assembled,
            original_disasm=instruction.get("disasm", ""),
            mutated_disasm=f"{prefix}; {jump}",
            mutation_kind="short_jump_patching",
            metadata={
                "original_mnemonic": mnemonic,
                "replacement": f"{prefix}; {jump}",
                "structural_baseline": baseline,
            },
        )
        if self._validate_mutation_or_rollback(binary, record, checkpoint):
            return False
        logger.info(f"Patched {mnemonic} at 0x{address:x} -> {prefix}; {jump} {target}")
        return True

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply short jump patching to the binary.

        Args:
            binary: Any to process

        Returns:
            Dictionary with patching statistics
        """
        self._reset_random()
        self._ensure_analyzed(binary)

        functions = binary.get_functions()
        total_patched = 0
        functions_patched = 0

        logger.info(f"Short jump patching: processing {len(functions)} functions")

        for func in functions:
            patches_in_func = 0
            for block in self._get_blocks(binary, func):
                for insn in self._disassemble_block(binary, block):
                    mnemonic = insn.get("mnemonic", "").lower()
                    if (
                        mnemonic not in SHORT_JUMP_EXCLUSIVE
                        or random.random() > self.patch_probability
                        or insn.get("size", 0) == 0
                    ):
                        continue
                    patch = self._assemble_patch(binary, func.get("addr", 0), insn)
                    if patch is None or not self._write_patch(binary, func.get("addr", 0), insn, patch):
                        continue
                    patches_in_func += 1
                    total_patched += 1

            if patches_in_func > 0:
                functions_patched += 1

        logger.info(
            f"Short jump patching complete: {total_patched} instructions patched in {functions_patched} functions"
        )

        return {
            "total_patched": total_patched,
            "functions_patched": functions_patched,
            "total_functions": len(functions),
        }


def detect_rip_relative_displacement(insn: dict[str, Any]) -> bool:
    """
    Detect if an instruction uses RIP-relative addressing.

    RIP-relative instructions are problematic for
    polymorphic code because the displacement changes when code moves.

    Args:
        insn: Instruction dictionary from disassembler

    Returns:
        True if instruction uses RIP-relative addressing
    """
    disasm = insn.get("disasm", "") or insn.get("opstr", "") or ""

    if "rip" in disasm.lower():
        return True

    esil = insn.get("esil", "")
    if "rip" in esil.lower():
        return True

    return bool(insn.get("type") in ["lea", "mov"] and "[rip" in disasm.lower())


def validate_instructions_for_rip_relative(instructions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Validate instructions for RIP-relative addressing.

    Returns a list of problematic instructions that
    use RIP-relative addressing, which cannot be safely mutated.

    Args:
        instructions: List of instruction dictionaries

    Returns:
        List of instructions with RIP-relative addressing
    """
    problematic = []

    for insn in instructions:
        if detect_rip_relative_displacement(insn):
            problematic.append(
                {
                    "address": insn.get("addr", 0),
                    "disasm": insn.get("disasm", "") or insn.get("opstr", ""),
                    "mnemonic": insn.get("mnemonic", ""),
                    "reason": "RIP-relative addressing detected",
                }
            )

    return problematic


class RIPRelativeValidationPass(MutationPass):
    """
    Mutation pass that validates code for RIP-relative instructions.

    RIP-relative instructions use offsets from the instruction pointer,
    which makes them position-dependent. When code is moved or modified,
    these offsets become invalid.

    This pass detects and reports such instructions, allowing other
    passes to handle them appropriately (skip, error, or relocate).
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="RIPRelativeValidation", config=config)
        self.fail_on_detect = self.config.get("fail_on_detect", True)

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Validate binary for RIP-relative instructions.

        Args:
            binary: Any to validate

        Returns:
            Dictionary with validation results
        """
        self._reset_random()
        self._ensure_analyzed(binary)

        functions = binary.get_functions()
        rip_relative_found = []
        functions_with_rip = 0

        logger.info(f"RIP-relative validation: checking {len(functions)} functions")

        for func in functions:
            try:
                blocks = binary.get_basic_blocks(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get blocks: {e}")
                continue

            func_has_rip = False

            for block in blocks:
                block_addr = block.get("addr", 0)
                block_size = block.get("size", 0)

                try:
                    insns = binary.r2.cmdj(f"pdj {block_size} @ 0x{block_addr:x}")
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    logger.debug("Cannot disassemble block at %#x: %s", block_addr, exc)
                    continue

                for insn in insns:
                    if detect_rip_relative_displacement(insn):
                        addr = insn.get("addr", 0)

                        if addr is None:
                            addr = 0

                        rip_relative_found.append(
                            {
                                "address": addr,
                                "function": func.get("name", f"0x{func.get('addr', 0):x}"),
                                "disasm": insn.get("disasm", "") or insn.get("opstr", ""),
                                "mnemonic": insn.get("mnemonic", ""),
                            }
                        )
                        func_has_rip = True

            if func_has_rip:
                functions_with_rip += 1

        if rip_relative_found and self.fail_on_detect:
            logger.warning(
                f"Found {len(rip_relative_found)} RIP-relative instructions in {functions_with_rip} functions"
            )
            for item in rip_relative_found[:_RIP_RELATIVE_PREVIEW_COUNT]:
                logger.warning(f"  0x{item['address']:x}: {item['disasm']} in {item['function']}")
            if len(rip_relative_found) > _RIP_RELATIVE_PREVIEW_COUNT:
                logger.warning(f"  ... and {len(rip_relative_found) - _RIP_RELATIVE_PREVIEW_COUNT} more")

        return {
            "valid": len(rip_relative_found) == 0,
            "rip_relative_count": len(rip_relative_found),
            "functions_with_rip": functions_with_rip,
            "rip_relative_instructions": rip_relative_found,
            "total_functions": len(functions),
        }
