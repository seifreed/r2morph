"""Conflict data models and overlap helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Map sub-registers to their 64-bit base register for conflict detection.
_REG_TO_BASE: dict[str, str] = {}
for _base, _variants in {
    "rax": ("eax", "ax", "al", "ah"),
    "rbx": ("ebx", "bx", "bl", "bh"),
    "rcx": ("ecx", "cx", "cl", "ch"),
    "rdx": ("edx", "dx", "dl", "dh"),
    "rsi": ("esi", "si", "sil"),
    "rdi": ("edi", "di", "dil"),
    "rbp": ("ebp", "bp", "bpl"),
    "rsp": ("esp", "sp", "spl"),
    "r8": ("r8d", "r8w", "r8b"),
    "r9": ("r9d", "r9w", "r9b"),
    "r10": ("r10d", "r10w", "r10b"),
    "r11": ("r11d", "r11w", "r11b"),
    "r12": ("r12d", "r12w", "r12b"),
    "r13": ("r13d", "r13w", "r13b"),
    "r14": ("r14d", "r14w", "r14b"),
    "r15": ("r15d", "r15w", "r15b"),
}.items():
    _REG_TO_BASE[_base] = _base
    for _variant in _variants:
        _REG_TO_BASE[_variant] = _base


def _normalize_registers(regs: set[str]) -> set[str]:
    """Normalize register names to their 64-bit base for conflict comparison."""
    return {_REG_TO_BASE.get(reg.lower(), reg.lower()) for reg in regs}


class ConflictType(Enum):
    """Types of mutation conflicts."""

    OVERLAP = "overlap"
    REGISTER_INTERFERENCE = "register_interference"
    MEMORY_INTERFERENCE = "memory_interference"
    CONTROL_FLOW = "control_flow"
    DEPENDENCY = "dependency"
    SEMANTIC = "semantic"


class ConflictSeverity(Enum):
    """Severity of a conflict."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MutationRegion:
    """Represents a region affected by a mutation."""

    start: int
    end: int
    pass_name: str = ""
    affected_registers: set[str] = field(default_factory=set)
    affected_memory: set[int] = field(default_factory=set)
    control_flow_changed: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.start, self.end, self.pass_name))

    def overlaps(self, other: MutationRegion) -> bool:
        """Check if this region overlaps with another."""
        return self.start < other.end and other.start < self.end

    def conflicts_with(self, other: MutationRegion) -> ConflictType | None:
        """
        Determine conflict type with another region.

        Args:
            other: Other mutation region

        Returns:
            ConflictType or None if no conflict
        """
        if self.overlaps(other):
            return ConflictType.OVERLAP

        if _normalize_registers(self.affected_registers) & _normalize_registers(other.affected_registers):
            return ConflictType.REGISTER_INTERFERENCE

        if self.affected_memory & other.affected_memory:
            return ConflictType.MEMORY_INTERFERENCE

        if self.control_flow_changed and other.control_flow_changed:
            return ConflictType.CONTROL_FLOW

        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "start": f"0x{self.start:x}",
            "end": f"0x{self.end:x}",
            "pass_name": self.pass_name,
            "affected_registers": sorted(self.affected_registers),
            "affected_memory": sorted(f"0x{a:x}" for a in self.affected_memory),
            "control_flow_changed": self.control_flow_changed,
        }


@dataclass
class Conflict:
    """Represents a conflict between two mutations."""

    conflict_id: int
    conflict_type: ConflictType
    severity: ConflictSeverity
    region1: MutationRegion
    region2: MutationRegion
    description: str = ""
    resolution_hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "conflict_id": self.conflict_id,
            "type": self.conflict_type.value,
            "severity": self.severity.value,
            "region1": self.region1.to_dict(),
            "region2": self.region2.to_dict(),
            "description": self.description,
            "resolution_hint": self.resolution_hint,
        }


@dataclass
class Resolution:
    """Represents a resolution for a conflict."""

    conflict: Conflict
    strategy: str
    description: str = ""
    action: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "conflict_id": self.conflict.conflict_id,
            "strategy": self.strategy,
            "description": self.description,
            "action": self.action,
        }


__all__ = [
    "Conflict",
    "ConflictSeverity",
    "ConflictType",
    "MutationRegion",
    "Resolution",
]
