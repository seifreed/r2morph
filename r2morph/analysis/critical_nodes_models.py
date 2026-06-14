"""Pure models for critical node analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AddressRange:
    """Represents a range of addresses."""

    start: int
    end: int

    def __contains__(self, address: int) -> bool:
        """Check if address is within this range."""
        return self.start <= address <= self.end

    def overlaps(self, other: AddressRange) -> bool:
        """Check if this range overlaps with another."""
        return self.start <= other.end and other.start <= self.end

    def merge(self, other: AddressRange) -> AddressRange:
        """Merge this range with another."""
        return AddressRange(
            start=min(self.start, other.start),
            end=max(self.end, other.end),
        )

    def size(self) -> int:
        """Get the size of this range."""
        return self.end - self.start + 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "start": f"0x{self.start:x}",
            "end": f"0x{self.end:x}",
            "size": self.size(),
        }


@dataclass
class CriticalNode:
    """Represents a critical node in the CFG."""

    address: int
    node_type: str
    reason: str
    exclusion_radius: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "address": f"0x{self.address:x}",
            "type": self.node_type,
            "reason": self.reason,
            "exclusion_radius": self.exclusion_radius,
        }
