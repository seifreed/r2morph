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
import random
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)

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

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply short jump patching to the binary.

        Args:
            binary: Any to process

        Returns:
            Dictionary with patching statistics
        """
        self._reset_random()
        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            binary.analyze()

        functions = binary.get_functions()
        total_patched = 0
        functions_patched = 0

        logger.info(f"Short jump patching: processing {len(functions)} functions")

        for func in functions:
            try:
                blocks = binary.get_basic_blocks(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get blocks for {func.get('name')}: {e}")
                continue

            patches_in_func = 0

            for block in blocks:
                block_addr = block.get("addr", 0)
                block_size = block.get("size", 0)

                if block_size < 1:
                    continue

                try:
                    insns = binary.r2.cmdj(f"pdj {block_size} @ 0x{block_addr:x}")
                except Exception as e:
                    logger.debug(f"Failed to disassemble block: {e}")
                    continue

                if not insns:
                    continue

                for insn in insns:
                    mnemonic = insn.get("mnemonic", "").lower()

                    if mnemonic not in SHORT_JUMP_EXCLUSIVE:
                        continue

                    if random.random() > self.patch_probability:
                        continue

                    replacement = self._get_replacement(mnemonic)
                    if not replacement:
                        continue

                    insn_addr = insn.get("addr", 0)
                    insn_size = insn.get("size", 0)

                    if insn_size == 0:
                        continue

                    operand = insn.get("jump", None)
                    if operand is None:
                        op_str = insn.get("opstr", "") or insn.get("disasm", "")
                        parts = op_str.split()
                        operand = parts[-1] if parts else None

                    if operand is None:
                        continue

                    if isinstance(operand, int):
                        target_label = f"0x{operand:x}"
                    else:
                        target_label = operand

                    prefix_insn, jump_insn = replacement

                    jump_asm = f"{prefix_insn}\n{jump_insn} {target_label}"

                    assembled = binary.assemble(jump_asm, function_addr=func.get("addr"))
                    if not assembled:
                        logger.debug(f"Failed to assemble replacement at 0x{insn_addr:x}")
                        continue

                    if len(assembled) > insn_size:
                        logger.debug(f"Replacement too large at 0x{insn_addr:x}: {len(assembled)} > {insn_size}")
                        continue

                    original_bytes = binary.read_bytes(insn_addr, insn_size)
                    if not original_bytes:
                        continue

                    mutation_checkpoint = self._create_mutation_checkpoint("short_jump")
                    baseline = {}
                    if self._validation_manager is not None:
                        baseline = self._validation_manager.capture_structural_baseline(binary, func.get("addr"))

                    if binary.write_bytes(insn_addr, assembled):
                        if len(assembled) < insn_size:
                            nop_count = insn_size - len(assembled)
                            nop_pad = binary.assemble("\n".join(["nop"] * nop_count), function_addr=func.get("addr"))
                            if nop_pad:
                                if not binary.write_bytes(insn_addr + len(assembled), nop_pad):
                                    logger.debug(f"Failed to write NOP padding at 0x{insn_addr + len(assembled):x}")
                                    continue

                        mutated_bytes = binary.read_bytes(insn_addr, insn_size)
                        record = self._record_mutation(
                            function_address=func.get("addr"),
                            start_address=insn_addr,
                            end_address=insn_addr + insn_size - 1,
                            original_bytes=original_bytes,
                            mutated_bytes=mutated_bytes if mutated_bytes else assembled,
                            original_disasm=insn.get("disasm", ""),
                            mutated_disasm=f"{prefix_insn}; {jump_insn}",
                            mutation_kind="short_jump_patching",
                            metadata={
                                "original_mnemonic": mnemonic,
                                "replacement": f"{prefix_insn}; {jump_insn}",
                                "structural_baseline": baseline,
                            },
                        )

                        if self._validation_manager is not None:
                            outcome = self._validation_manager.validate_mutation(binary, record.to_dict())
                            if not outcome.passed and mutation_checkpoint is not None:
                                if self._session is not None:
                                    self._session.rollback_to(mutation_checkpoint)
                                binary.reload()
                                if self._records:
                                    self._records.pop()
                                if self._rollback_policy == "fail-fast":
                                    raise RuntimeError("Mutation-level validation failed")
                                continue

                        patches_in_func += 1
                        total_patched += 1
                        logger.info(
                            f"Patched {mnemonic} at 0x{insn_addr:x} -> {prefix_insn}; {jump_insn} {target_label}"
                        )

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
    insn.get("mnemonic", "").lower()

    if "rip" in disasm.lower():
        return True

    esil = insn.get("esil", "")
    if "rip" in esil.lower():
        return True

    if insn.get("type") in ["lea", "mov"] and "[rip" in disasm.lower():
        return True

    return False


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
        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            binary.analyze()

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
                except Exception:
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
            for item in rip_relative_found[:5]:
                logger.warning(f"  0x{item['address']:x}: {item['disasm']} in {item['function']}")
            if len(rip_relative_found) > 5:
                logger.warning(f"  ... and {len(rip_relative_found) - 5} more")

        return {
            "valid": len(rip_relative_found) == 0,
            "rip_relative_count": len(rip_relative_found),
            "functions_with_rip": functions_with_rip,
            "rip_relative_instructions": rip_relative_found,
            "total_functions": len(functions),
        }
