"""
Assembly service for instruction encoding with intelligent fallbacks.

Extracted from Binary class following Single Responsibility Principle.
"""

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


# Register encoding tables for manual instruction encoding
REGISTER_ENCODING = {
    "reg32": {
        "eax": 0,
        "ecx": 1,
        "edx": 2,
        "ebx": 3,
        "esp": 4,
        "ebp": 5,
        "esi": 6,
        "edi": 7,
    },
    "reg16": {
        "ax": 0,
        "cx": 1,
        "dx": 2,
        "bx": 3,
        "sp": 4,
        "bp": 5,
        "si": 6,
        "di": 7,
    },
    "reg8": {
        "al": 0,
        "cl": 1,
        "dl": 2,
        "bl": 3,
        "ah": 4,
        "ch": 5,
        "dh": 6,
        "bh": 7,
    },
    "reg64": {
        "rax": 0,
        "rcx": 1,
        "rdx": 2,
        "rbx": 3,
        "rsp": 4,
        "rbp": 5,
        "rsi": 6,
        "rdi": 7,
        "r8": 8,
        "r9": 9,
        "r10": 10,
        "r11": 11,
        "r12": 12,
        "r13": 13,
        "r14": 14,
        "r15": 15,
    },
}


class AssemblyService:
    """
    Service for assembling instructions using radare2 with intelligent fallbacks.

    Handles assembly quirks with manual encoding for:
    - movzx/movsx register-to-register operations
    - Segment prefix instructions (fs:, gs:, etc.)
    - Symbolic variable resolution
    """

    def __init__(self):
        """Initialize AssemblyService."""
        pass

    def assemble(self, binary: "Binary", instruction: str, function_addr: int | None = None) -> bytes | None:
        """
        Assemble an instruction using radare2's rasm2 with intelligent fallbacks.

        Args:
            binary: Binary instance with r2pipe connection
            instruction: Assembly instruction (e.g., "nop", "xor eax, eax")
            function_addr: Function address for resolving symbolic variables (optional)

        Returns:
            Assembled bytes or None if failed
        """
        if not binary.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        try:
            # Resolve symbolic variables to actual addresses
            resolved_instruction = self._resolve_symbolic_vars(binary, instruction, function_addr)

            # Normalize syntax for radare2 assembler compatibility
            normalized_instruction = self._normalize_assembly_syntax(resolved_instruction)

            # Try standard radare2 assembler first
            result = binary.r2.cmd(f"pa {normalized_instruction}")
            hex_str = result.strip()
            if hex_str:
                try:
                    return bytes.fromhex(hex_str)
                except ValueError as e:
                    logger.error(f"Failed to parse hex '{hex_str[:20]}...': {e}")

            # If radare2 failed, try intelligent fallbacks

            # Fallback 1: movzx/movsx manual encoding
            if normalized_instruction.strip().lower().startswith(("movzx", "movsx")):
                logger.debug("Radare2 assembler failed, trying manual movzx/movsx encoding")
                manual_bytes = self._assemble_movzx_movsx_fallback(normalized_instruction)
                if manual_bytes:
                    logger.debug(f"  Successfully encoded: {manual_bytes.hex()}")
                    return manual_bytes

            # Fallback 2: segment prefix instructions (fs:, gs:, etc.)
            if any(seg in normalized_instruction.lower() for seg in ["fs:", "gs:", "es:", "ds:", "ss:", "cs:"]):
                logger.debug("Radare2 assembler failed, trying segment prefix fallback")
                segment_bytes = self._assemble_segment_prefix_fallback(binary, normalized_instruction)
                if segment_bytes:
                    logger.debug(f"  Successfully encoded: {segment_bytes.hex()}")
                    return segment_bytes

            # All fallbacks exhausted
            hex_str = result.strip() if result else ""
            logger.error(f"Failed to assemble: {instruction}, r2 returned: {hex_str[:50] if hex_str else 'empty'}")
            if normalized_instruction != instruction:
                logger.debug(f"  After normalization: {normalized_instruction}")
            return None

        except (ValueError, OSError) as e:
            logger.error(f"Assembly error for '{instruction}': {e}")
            return None

    def _resolve_symbolic_vars(self, binary: "Binary", instruction: str, function_addr: int | None = None) -> str:
        """Resolve symbolic variable names in instruction to actual addresses.

        Delegates to BinaryReader.resolve_symbolic_vars() to avoid duplication.
        """
        return binary._resolve_symbolic_vars(instruction, function_addr)

    def _normalize_assembly_syntax(self, instruction: str) -> str:
        """
        Normalize assembly syntax to work around radare2 assembler quirks.

        Args:
            instruction: Assembly instruction

        Returns:
            Normalized instruction
        """
        # No longer removing size specifiers with segment prefixes
        # The segment prefix fallback will handle these correctly
        return instruction

    def _assemble_movzx_movsx_fallback(self, instruction: str) -> bytes | None:
        """
        Manually encode movzx/movsx instructions using direct opcodes.

        Radare2's assembler fails on register-to-register movzx/movsx but works on memory operands.
        This fallback manually constructs the opcodes for reg-to-reg cases.

        Args:
            instruction: movzx/movsx instruction (e.g., "movzx eax, bl")

        Returns:
            Assembled bytes or None if cannot encode
        """
        # Parse instruction: movzx/movsx dest, src
        match = re.match(r"(movzx|movsx)\s+(\w+),\s*(\w+)", instruction.strip(), re.IGNORECASE)
        if not match:
            return None

        mnemonic, dest, src = match.groups()
        mnemonic = mnemonic.lower()
        dest = dest.lower()
        src = src.lower()

        reg32_encoding = REGISTER_ENCODING["reg32"]
        reg16_encoding = REGISTER_ENCODING["reg16"]
        reg8_encoding = REGISTER_ENCODING["reg8"]
        reg64_encoding = REGISTER_ENCODING["reg64"]

        # Determine opcode based on source size and operation
        if src in reg8_encoding:
            # Source is 8-bit
            opcode = bytes([0x0F, 0xB6 if mnemonic == "movzx" else 0xBE])
            src_code = reg8_encoding[src]
        elif src in reg16_encoding:
            # Source is 16-bit
            opcode = bytes([0x0F, 0xB7 if mnemonic == "movzx" else 0xBF])
            src_code = reg16_encoding[src]
        else:
            # Unknown source register size
            return None

        # Determine destination encoding
        rex = 0
        if dest in reg32_encoding:
            dest_code = reg32_encoding[dest]
        elif dest in reg64_encoding:
            dest_code = reg64_encoding[dest]
            if dest_code >= 8:
                # High register (r8-r15): REX.R bit extends ModR/M reg field
                rex |= 0x44  # REX + REX.R
                dest_code &= 0x07
            else:
                rex |= 0x48  # REX.W for 64-bit operand size
        else:
            return None

        # Construct ModR/M byte: 11 (register mode) + dest<<3 + src
        modrm = 0xC0 | (dest_code << 3) | src_code

        if rex:
            return bytes([rex]) + opcode + bytes([modrm])
        return opcode + bytes([modrm])

    def _assemble_segment_prefix_fallback(self, binary: "Binary", instruction: str) -> bytes | None:
        """
        Manually encode instructions with segment prefixes (fs:, gs:, etc.).

        Radare2's assembler fails on segment-prefixed instructions.
        This fallback removes the segment prefix, assembles without it, then adds the prefix byte.

        Args:
            binary: Binary instance with r2pipe connection
            instruction: Instruction with segment prefix (e.g., "mov fs:[rax], ecx")

        Returns:
            Assembled bytes with segment prefix or None if failed
        """
        segment_prefixes = {
            "es:": 0x26,
            "cs:": 0x2E,
            "ss:": 0x36,
            "ds:": 0x3E,
            "fs:": 0x64,
            "gs:": 0x65,
        }

        segment_byte = None
        instruction_without_segment = instruction
        for seg_name, seg_byte in segment_prefixes.items():
            if seg_name in instruction.lower():
                segment_byte = seg_byte
                instruction_without_segment = instruction.replace(seg_name, "", 1)
                instruction_without_segment = instruction_without_segment.replace(seg_name.upper(), "", 1)
                break

        if segment_byte is None:
            return None

        if not binary.r2:
            return None

        result = binary.r2.cmd(f"pa {instruction_without_segment}")
        hex_str = result.strip() if result else ""
        if hex_str:
            for c in hex_str:
                if c not in "0123456789abcdefABCDEF":
                    logger.debug(f"Invalid hex in segment prefix fallback: {hex_str[:20]}...")
                    return None
            try:
                base_bytes = bytes.fromhex(hex_str)
                return bytes([segment_byte]) + base_bytes
            except ValueError:
                logger.debug(f"Failed to parse hex in segment prefix fallback: {hex_str[:20]}...")
                return None

        return None


# Singleton instance for convenience
_default_assembly_service: AssemblyService | None = None


def get_assembly_service() -> AssemblyService:
    """Get the default AssemblyService instance."""
    global _default_assembly_service
    if _default_assembly_service is None:
        _default_assembly_service = AssemblyService()
    return _default_assembly_service
