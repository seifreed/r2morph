"""SSA model types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SSAVariable:
    """Represents an SSA variable with version number."""

    base_name: str
    version: int
    original_register: str | None = None
    definition_address: int | None = None

    def __repr__(self) -> str:
        return f"{self.base_name}_{self.version}"

    def __hash__(self) -> int:
        return hash((self.base_name, self.version))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SSAVariable):
            return False
        return self.base_name == other.base_name and self.version == other.version


@dataclass
class PhiFunction:
    """Phi function for SSA at control flow merge points."""

    result: SSAVariable
    operands: list[SSAVariable]
    block_address: int

    def __repr__(self) -> str:
        operands_str = ", ".join(str(op) for op in self.operands)
        return f"{self.result} = φ({operands_str})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": str(self.result),
            "operands": [str(op) for op in self.operands],
            "block_address": f"0x{self.block_address:x}",
        }


@dataclass
class SSABlock:
    """Basic block in SSA form."""

    address: int
    instructions: list[dict[str, Any]] = field(default_factory=list)
    phi_functions: list[PhiFunction] = field(default_factory=list)
    definitions: dict[str, SSAVariable] = field(default_factory=dict)
    live_in: set[SSAVariable] = field(default_factory=set)
    live_out: set[SSAVariable] = field(default_factory=set)
    predecessors: list[int] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": f"0x{self.address:x}",
            "phi_functions": [phi.to_dict() for phi in self.phi_functions],
            "definitions": {k: str(v) for k, v in self.definitions.items()},
            "predecessors": [f"0x{p:x}" for p in self.predecessors],
            "successors": [f"0x{s:x}" for s in self.successors],
        }
