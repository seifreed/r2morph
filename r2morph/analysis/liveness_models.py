"""Shared liveness model types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from r2morph.analysis.dataflow_models import Register

_X86_REGISTER_BIT_SIZES = {
    "rax": 64,
    "rbx": 64,
    "rcx": 64,
    "rdx": 64,
    "rsi": 64,
    "rdi": 64,
    "rbp": 64,
    "rsp": 64,
    "r8": 64,
    "r9": 64,
    "r10": 64,
    "r11": 64,
    "r12": 64,
    "r13": 64,
    "r14": 64,
    "r15": 64,
    "eax": 32,
    "ebx": 32,
    "ecx": 32,
    "edx": 32,
    "esi": 32,
    "edi": 32,
    "ebp": 32,
    "esp": 32,
    "r8d": 32,
    "r9d": 32,
    "r10d": 32,
    "r11d": 32,
    "r12d": 32,
    "r13d": 32,
    "r14d": 32,
    "r15d": 32,
    "ax": 16,
    "bx": 16,
    "cx": 16,
    "dx": 16,
    "si": 16,
    "di": 16,
    "bp": 16,
    "sp": 16,
    "r8w": 16,
    "r9w": 16,
    "r10w": 16,
    "r11w": 16,
    "r12w": 16,
    "r13w": 16,
    "r14w": 16,
    "r15w": 16,
    "al": 8,
    "bl": 8,
    "cl": 8,
    "dl": 8,
    "sil": 8,
    "dil": 8,
    "bpl": 8,
    "spl": 8,
    "r8b": 8,
    "r9b": 8,
    "r10b": 8,
    "r11b": 8,
    "r12b": 8,
    "r13b": 8,
    "r14b": 8,
    "r15b": 8,
}


@dataclass
class LiveRange:
    """Represents the live range of a register."""

    register: Register
    start_address: int
    end_address: int
    definition_address: int | None = None
    use_addresses: list[int] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"<LiveRange {self.register} 0x{self.start_address:x}-0x{self.end_address:x}>"

    def contains(self, address: int) -> bool:
        """Check if address is within this live range."""
        return self.start_address <= address <= self.end_address

    def overlaps(self, other: LiveRange) -> bool:
        """Check if this live range overlaps with another."""
        if self.register.name != other.register.name:
            return False
        return self.start_address <= other.end_address and other.start_address <= self.end_address

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "register": self.register.name,
            "start": f"0x{self.start_address:x}",
            "end": f"0x{self.end_address:x}",
            "definition": f"0x{self.definition_address:x}" if self.definition_address else None,
            "uses": [f"0x{addr:x}" for addr in self.use_addresses],
        }


@dataclass
class InstructionLiveness:
    """Liveness information at a specific instruction."""

    address: int
    instruction: str
    live_before: set[Register] = field(default_factory=set)
    live_after: set[Register] = field(default_factory=set)
    defined: set[Register] = field(default_factory=set)
    used: set[Register] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "address": f"0x{self.address:x}",
            "instruction": self.instruction,
            "live_before": sorted([r.name for r in self.live_before]),
            "live_after": sorted([r.name for r in self.live_after]),
            "defined": sorted([r.name for r in self.defined]),
            "used": sorted([r.name for r in self.used]),
        }


@dataclass
class InterferenceGraph:
    """Interference graph for register allocation."""

    edges: dict[str, set[str]] = field(default_factory=dict)

    def add_node(self, register: str) -> None:
        """Add a node to the graph."""
        if register not in self.edges:
            self.edges[register] = set()

    def add_edge(self, reg1: str, reg2: str) -> None:
        """Add an interference edge between two registers."""
        self.add_node(reg1)
        self.add_node(reg2)
        if reg1 != reg2:
            self.edges[reg1].add(reg2)
            self.edges[reg2].add(reg1)

    def interfere(self, reg1: str, reg2: str) -> bool:
        """Check if two registers interfere."""
        return reg2 in self.edges.get(reg1, set())

    def get_neighbors(self, register: str) -> set[str]:
        """Get all registers that interfere with the given register."""
        return self.edges.get(register, set())

    def get_nodes(self) -> set[str]:
        """Get all register nodes in the graph."""
        return set(self.edges.keys())

    def to_dict(self) -> dict[str, list[str]]:
        """Convert to dictionary."""
        return {reg: sorted(neighbors) for reg, neighbors in self.edges.items()}
