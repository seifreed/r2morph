"""
Instruction representation for binary analysis.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Instruction:
    """
    Represents a single assembly instruction.

    Attributes:
        address: Instruction address
        mnemonic: Instruction mnemonic (e.g., 'mov', 'add')
        operands: List of operands
        size: Instruction size in bytes
        bytes: Raw instruction bytes
        type: Instruction type (mov, call, jmp, etc.)
        metadata: Additional metadata from radare2
    """

    address: int
    mnemonic: str
    operands: list[str]
    size: int
    bytes: bytes
    type: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_r2_dict(cls, data: dict[str, Any]) -> "Instruction":
        """
        Create Instruction instance from radare2 JSON output.

        Args:
            data: Dictionary from radare2 'pdfj' command ops

        Returns:
            Instruction instance
        """
        disasm = data.get("disasm", "")
        parts = disasm.split(None, 1)
        mnemonic = parts[0] if parts else ""
        operands_str = parts[1] if len(parts) > 1 else ""
        operands = [op.strip() for op in operands_str.split(",")] if operands_str else []

        raw_hex = data.get("bytes", "")
        raw_bytes = b""
        if raw_hex:
            raw_hex = raw_hex.strip()
            for c in raw_hex:
                if c not in "0123456789abcdefABCDEF":
                    logger.debug(f"Invalid hex character in instruction bytes: {c}")
                    raw_hex = ""
                    break
            if raw_hex:
                try:
                    raw_bytes = bytes.fromhex(raw_hex)
                except ValueError as e:
                    logger.debug(f"Failed to parse hex bytes '{raw_hex[:20]}...': {e}")
                    raw_bytes = b""

        size = data.get("size", 0)
        if size > 0 and len(raw_bytes) > 0 and len(raw_bytes) != size:
            logger.debug(f"Size mismatch at 0x{data.get('offset', 0):x}: expected {size}, got {len(raw_bytes)} bytes")

        return cls(
            address=data.get("offset", 0),
            mnemonic=mnemonic,
            operands=operands,
            size=size,
            bytes=raw_bytes,
            type=data.get("type", "unknown"),
            metadata=data,
        )

    def is_jump(self) -> bool:
        """Check if instruction is a jump."""
        return self.type in ["jmp", "cjmp", "ujmp"]

    def is_call(self) -> bool:
        """Check if instruction is a call."""
        return self.type == "call"

    def is_ret(self) -> bool:
        """Check if instruction is a return."""
        return self.type == "ret"

    def is_nop(self) -> bool:
        """Check if instruction is a NOP."""
        return self.mnemonic.lower() == "nop"

    def is_conditional(self) -> bool:
        """Check if instruction is conditional."""
        return self.type == "cjmp" or self.mnemonic.startswith(("cmov", "j"))

    def get_jump_target(self) -> int | None:
        """
        Get jump target address if this is a jump instruction.

        Returns:
            Target address or None
        """
        if self.is_jump():
            return self.metadata.get("jump")
        return None

    def get_call_target(self) -> int | None:
        """
        Get call target address if this is a call instruction.

        Returns:
            Target address or None
        """
        if self.is_call():
            return self.metadata.get("jump")
        return None

    def __repr__(self) -> str:
        ops = ", ".join(self.operands)
        return f"<Instruction {self.mnemonic} {ops} @ 0x{self.address:x}>"

    def __str__(self) -> str:
        ops = ", ".join(self.operands)
        return f"{self.mnemonic} {ops}".strip()
