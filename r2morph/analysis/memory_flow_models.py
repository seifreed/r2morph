"""Pure models for memory flow analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MemoryAccessType(Enum):
    """Type of memory access."""

    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"
    ALLOC = "alloc"
    FREE = "free"


@dataclass
class MemoryLocation:
    """Represents a memory location."""

    address: int
    size: int
    name: str = ""
    location_type: str = "unknown"  # stack, heap, global, unknown

    def __hash__(self) -> int:
        return hash((self.address, self.size))

    def __repr__(self) -> str:
        if self.name:
            return f"<Mem 0x{self.address:x}:{self.size} {self.name}>"
        return f"<Mem 0x{self.address:x}:{self.size}>"

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": f"0x{self.address:x}",
            "size": self.size,
            "name": self.name,
            "type": self.location_type,
        }

    def overlaps(self, other: MemoryLocation) -> bool:
        """Check if this location overlaps with another."""
        return self.address < other.address + other.size and other.address < self.address + self.size


@dataclass
class MemoryAccess:
    """Represents a memory access at a specific instruction."""

    address: int  # Instruction address
    location: MemoryLocation
    access_type: MemoryAccessType
    instruction: str = ""
    registers_involved: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "instruction_address": f"0x{self.address:x}",
            "location": self.location.to_dict(),
            "access_type": self.access_type.value,
            "instruction": self.instruction,
            "registers": self.registers_involved,
        }


@dataclass
class MemoryDependency:
    """Represents a dependency between memory accesses."""

    source: MemoryAccess
    target: MemoryAccess
    dependency_type: str  # flow, anti, output
    is_alias: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "target": self.target.to_dict(),
            "type": self.dependency_type,
            "alias": self.is_alias,
        }


@dataclass(frozen=True)
class _DecodedAccess:
    """A memory access decoded from a single instruction, before recording."""

    access_type: MemoryAccessType
    size: int
    address: int
    location_name: str
    registers: list[str]
