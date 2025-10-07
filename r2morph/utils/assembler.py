"""
Assembler utilities using radare2's native rasm2.

No need for Keystone - radare2 has a built-in assembler!
"""

import logging

logger = logging.getLogger(__name__)


class R2Assembler:
    """
    Wrapper around radare2's rasm2 assembler.

    Uses radare2's native assembly capabilities instead of Keystone.
    """

    def __init__(self, r2_instance):
        """
        Initialize assembler.

        Args:
            r2_instance: r2pipe instance
        """
        self.r2 = r2_instance

    def assemble(self, instruction: str, address: int = 0) -> bytes | None:
        """
        Assemble a single instruction to bytes.

        Args:
            instruction: Assembly instruction (e.g., "nop", "xor eax, eax")
            address: Optional address for position-dependent instructions

        Returns:
            Assembled bytes or None if assembly failed

        Examples:
            >>> asm = R2Assembler(r2)
            >>> asm.assemble("nop")
            b'\\x90'
            >>> asm.assemble("xor eax, eax")
            b'\\x31\\xc0'
        """
        try:
            if address:
                result = self.r2.cmd(f'"pa {instruction}" @ {address}')
            else:
                result = self.r2.cmd(f"pa {instruction}")

            hex_str = result.strip()
            if hex_str:
                return bytes.fromhex(hex_str)
            else:
                logger.error(f"Failed to assemble: {instruction}")
                return None

        except Exception as e:
            logger.error(f"Assembly error for '{instruction}': {e}")
            return None

    def assemble_multiple(self, instructions: list[str]) -> bytes | None:
        """
        Assemble multiple instructions.

        Args:
            instructions: List of assembly instructions

        Returns:
            Assembled bytes or None if assembly failed

        Examples:
            >>> asm.assemble_multiple(["push ebp", "mov ebp, esp"])
            b'\\x55\\x89\\xe5'
        """
        all_bytes = b""

        for insn in instructions:
            insn_bytes = self.assemble(insn)
            if insn_bytes is None:
                logger.error(f"Failed to assemble: {insn}")
                return None
            all_bytes += insn_bytes

        return all_bytes

    def get_instruction_size(self, instruction: str) -> int:
        """
        Get the size in bytes of an assembled instruction.

        Args:
            instruction: Assembly instruction

        Returns:
            Size in bytes (0 if assembly failed)
        """
        assembled = self.assemble(instruction)
        return len(assembled) if assembled else 0

    def disassemble(self, data: bytes, address: int = 0) -> str | None:
        """
        Disassemble bytes to assembly.

        Args:
            data: Bytes to disassemble
            address: Optional address for display

        Returns:
            Disassembled instruction or None

        Examples:
            >>> asm.disassemble(b'\\x90')
            'nop'
            >>> asm.disassemble(b'\\x31\\xc0')
            'xor eax, eax'
        """
        try:
            hex_str = data.hex()

            result = self.r2.cmd(f"pad {hex_str}")

            return result.strip() if result else None

        except Exception as e:
            logger.error(f"Disassembly error: {e}")
            return None


COMMON_OPCODES_X64 = {
    "nop": b"\x90",
    "xor eax, eax": b"\x31\xc0",
    "xor ebx, ebx": b"\x31\xdb",
    "xor ecx, ecx": b"\x31\xc9",
    "xor edx, edx": b"\x31\xd2",
    "xor rax, rax": b"\x48\x31\xc0",
    "xor rbx, rbx": b"\x48\x31\xdb",
    "inc eax": b"\xff\xc0",
    "dec eax": b"\xff\xc8",
    "inc rax": b"\x48\xff\xc0",
    "dec rax": b"\x48\xff\xc8",
    "ret": b"\xc3",
    "retn": b"\xc3",
    "push rax": b"\x50",
    "push rbx": b"\x53",
    "push rcx": b"\x51",
    "push rdx": b"\x52",
    "pop rax": b"\x58",
    "pop rbx": b"\x5b",
    "pop rcx": b"\x59",
    "pop rdx": b"\x5a",
}


def get_common_opcode(instruction: str) -> bytes | None:
    """
    Get opcode for common instructions from lookup table.

    This is faster than assembling but only works for common patterns.
    For anything else, use R2Assembler.assemble()

    Args:
        instruction: Assembly instruction

    Returns:
        Opcode bytes or None if not in common table
    """
    return COMMON_OPCODES_X64.get(instruction.lower())
