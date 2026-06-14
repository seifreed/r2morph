"""Semantic invariant data models and registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class InvariantCategory(Enum):
    """Category of semantic invariant."""

    STACK = "stack"
    REGISTER = "register"
    MEMORY = "memory"
    CONTROL_FLOW = "control_flow"
    SIDE_EFFECT = "side_effect"
    ABI = "abi"


class InvariantSeverity(Enum):
    """Severity level for invariant violations."""

    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class InvariantSpec:
    """Specification of a semantic invariant."""

    name: str
    category: InvariantCategory
    description: str
    check_required: bool = True
    auto_repair: bool = False
    pass_types: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class InvariantViolation:
    """Represents a violation of a semantic invariant."""

    invariant_name: str
    category: InvariantCategory
    severity: InvariantSeverity
    address_range: tuple[int, int]
    message: str
    expected: Any | None = None
    actual: Any | None = None
    repair_hint: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "invariant_name": self.invariant_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "address_range": [self.address_range[0], self.address_range[1]],
            "message": self.message,
            "expected": str(self.expected) if self.expected else None,
            "actual": str(self.actual) if self.actual else None,
            "repair_hint": self.repair_hint,
            "metadata": self.metadata,
        }


class SemanticInvariantRegistry:
    """Registry of semantic invariants for mutation passes."""

    def __init__(self) -> None:
        """Initialize the invariant registry."""
        from r2morph.validation.semantic_invariant_catalogs import STANDARD_INVARIANTS

        self._invariants: dict[str, InvariantSpec] = {inv.name: inv for inv in STANDARD_INVARIANTS}
        self._pass_invariants: dict[str, list[str]] = {}
        self._build_pass_index()

    def _build_pass_index(self) -> None:
        """Build index of invariants by pass type."""
        self._pass_invariants = {}
        for inv in self._invariants.values():
            for pass_type in inv.pass_types:
                if pass_type not in self._pass_invariants:
                    self._pass_invariants[pass_type] = []
                self._pass_invariants[pass_type].append(inv.name)

    def register_invariant(self, invariant: InvariantSpec) -> None:
        """Register a new invariant."""
        self._invariants[invariant.name] = invariant
        self._build_pass_index()

    def get_invariants_for_pass(self, pass_type: str) -> list[InvariantSpec]:
        """Get all invariants that apply to a pass type."""
        return [self._invariants[name] for name in self._pass_invariants.get(pass_type, []) if name in self._invariants]

    def get_required_invariants(self, pass_type: str) -> list[InvariantSpec]:
        """Get only required invariants for a pass type."""
        return [inv for inv in self.get_invariants_for_pass(pass_type) if inv.check_required]
