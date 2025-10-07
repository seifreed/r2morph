"""
Function representation for binary analysis.
"""

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class Function:
    """
    Represents a function in the binary.

    Attributes:
        address: Function start address
        name: Function name
        size: Function size in bytes
        instructions: List of instructions in the function
        basic_blocks: List of basic blocks
        calls: List of called functions
        metadata: Additional metadata from radare2
    """

    address: int
    name: str
    size: int
    instructions: list[dict[str, Any]]
    basic_blocks: list[Dict[str, Any]]
    calls: List[int]
    metadata: Dict[str, Any]

    @classmethod
    def from_r2_dict(cls, data: dict[str, Any]) -> "Function":
        """
        Create Function instance from radare2 JSON output.

        Args:
            data: Dictionary from radare2 'aflj' command

        Returns:
            Function instance
        """
        return cls(
            address=data.get("offset", 0),
            name=data.get("name", "unknown"),
            size=data.get("size", 0),
            instructions=[],
            basic_blocks=[],
            calls=data.get("callrefs", []),
            metadata=data,
        )

    def get_instructions_count(self) -> int:
        """Get number of instructions in function."""
        return len(self.instructions)

    def get_complexity(self) -> int:
        """
        Calculate cyclomatic complexity (basic block count).

        Returns:
            Number of basic blocks as complexity metric
        """
        return len(self.basic_blocks)

    def is_leaf(self) -> bool:
        """Check if function is a leaf (no calls)."""
        return len(self.calls) == 0

    def __repr__(self) -> str:
        return f"<Function {self.name} @ 0x{self.address:x} size={self.size}>"
