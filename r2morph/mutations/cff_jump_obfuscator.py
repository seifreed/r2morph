"""Unconditional-jump obfuscation extracted from ControlFlowFlatteningPass.

Slice 5 of the CFF clean-arch decomposition: in-place short-jump
rewriting plus its target/size analyzer. Plain intra-mutations/
collaborator (no protocol, per the ValidationManager precedent);
imports only `re` and the shared dead-code utility, so the direct
import in control_flow_flattening.py introduces no cycle.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from r2morph.utils.dead_code import generate_nop_sequence

logger = logging.getLogger(__name__)


class JumpObfuscator:
    """Rewrites short unconditional jumps in place to add analysis resistance."""

    def obfuscate_jump(self, binary: Any, jump_insn: dict, block: dict, arch: str, bits: int) -> bool:
        """
        Obfuscate an unconditional jump instruction.

        Techniques:
        1. Replace direct jump with computed jump (harder to analyze)
        2. Add unnecessary intermediate jumps
        3. Use indirect addressing where possible

        Note: This is limited by available space - we can only transform
        the jump in-place without expanding the function.

        Args:
            binary: Any instance
            jump_insn: The jump instruction dictionary
            block: The containing basic block
            arch: Architecture family
            bits: Bit width

        Returns:
            True if successfully obfuscated
        """
        jump_addr = jump_insn.get("offset", 0)
        jump_size = jump_insn.get("size", 0)

        # For now, we can only do in-place transformations
        # Skip if jump is too small to modify meaningfully
        if jump_size < 5:
            return False

        disasm = jump_insn.get("disasm", "")
        if not disasm:
            return False

        # Try to parse the target address
        try:
            # Format is usually "jmp 0x12345678" or "jmp target_name"
            parts = disasm.split()
            if len(parts) >= 2:
                target_str = parts[1]
                if target_str.startswith("0x"):
                    target_addr = int(target_str, 16)
                else:
                    # Named target - skip for now
                    return False
            else:
                return False
        except (ValueError, IndexError):
            return False

        if arch == "x86":
            jump_info = self.analyze_jump_target(binary, jump_insn, jump_addr, arch, bits)
            if jump_info is None:
                return False

            target_addr = jump_info["target"]
            current_jump_size = jump_info["size"]

            if current_jump_size < 5:
                logger.debug(f"Jump at 0x{jump_addr:x} too small for obfuscation")
                return False

            rel_offset = target_addr - (jump_addr + 2)
            if -128 <= rel_offset <= 127:
                new_insn = f"jmp 0x{target_addr:x}"
                assembled = binary.assemble(new_insn, jump_addr)

                if assembled and len(assembled) <= current_jump_size:
                    padded = assembled + generate_nop_sequence(arch, bits, current_jump_size - len(assembled))
                    return bool(binary.write_bytes(jump_addr, padded))

            long_rel_offset = target_addr - (jump_addr + 5)
            if -2147483648 <= long_rel_offset <= 2147483647:
                new_insn = f"jmp 0x{target_addr:x}"
                assembled = binary.assemble(new_insn, jump_addr)

                if assembled and len(assembled) <= current_jump_size:
                    padded = assembled + generate_nop_sequence(arch, bits, current_jump_size - len(assembled))
                    return bool(binary.write_bytes(jump_addr, padded))

            logger.debug(f"Could not obfuscate jump at 0x{jump_addr:x} - assembly failed or size mismatch")
            return False

        logger.debug(f"Jump obfuscation not supported for architecture: {arch}")
        return False

    @staticmethod
    def analyze_jump_target(binary: Any, jump_insn: dict, jump_addr: int, arch: str, bits: int) -> dict | None:
        """
        Analyze jump instruction to extract target and size.

        Args:
            binary: Any instance
            jump_insn: Jump instruction dictionary
            jump_addr: Address of jump instruction
            arch: Architecture family
            bits: Bit width

        Returns:
            Dict with 'target' and 'size', or None if analysis fails
        """
        try:
            disasm = jump_insn.get("disasm", "")
            if not disasm:
                return None

            if "jmp" not in disasm.lower()[:3]:
                return None

            jump_size = jump_insn.get("size", 0)
            if jump_size == 0:
                return None

            addr_match = re.search(r"0x([0-9a-fA-F]+)", disasm)
            if addr_match:
                return {"target": int(addr_match.group(1), 16), "size": jump_size}

            return None
        except (ValueError, KeyError, TypeError) as e:
            logger.debug(f"Failed to analyze jump target: {e}")
            return None
