"""Semantic-validation input data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.validation.semantic_invariant_models import InvariantCategory


class ValidationMode(Enum):
    """Semantic validation mode."""

    FAST = "fast"
    STANDARD = "standard"
    THOROUGH = "thorough"


class ValidationResultStatus(Enum):
    """Status of semantic validation result."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIP = "skip"


@dataclass
class MutationRegion:
    """Represents a mutated code region."""

    start_address: int
    end_address: int
    original_bytes: bytes
    mutated_bytes: bytes
    pass_name: str
    function_address: int | None = None
    original_disasm: str | None = None
    mutated_disasm: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "start_address": self.start_address,
            "end_address": self.end_address,
            "original_bytes": self.original_bytes.hex(),
            "mutated_bytes": self.mutated_bytes.hex(),
            "pass_name": self.pass_name,
            "function_address": self.function_address,
            "original_disasm": self.original_disasm,
            "mutated_disasm": self.mutated_disasm,
            "metadata": self.metadata,
        }


@dataclass
class SemanticCheck:
    """Represents a single semantic check."""

    check_name: str
    category: InvariantCategory
    passed: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "check_name": self.check_name,
            "category": self.category.value,
            "passed": self.passed,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ObservableComparison:
    """Comparison of observables between original and mutated."""

    register_matches: dict[str, bool] = field(default_factory=dict)
    register_values: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    flag_matches: dict[str, bool] = field(default_factory=dict)
    memory_matches: dict[int, bool] = field(default_factory=dict)
    stack_delta_match: bool = True
    successor_match: bool = True
    successor_addresses: tuple[list[int], list[int]] = field(default_factory=lambda: ([], []))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "register_matches": self.register_matches,
            "register_values": {
                k: {"original": str(v[0]), "mutated": str(v[1])} for k, v in self.register_values.items()
            },
            "flag_matches": self.flag_matches,
            "memory_matches": {hex(k): v for k, v in self.memory_matches.items()},
            "stack_delta_match": self.stack_delta_match,
            "successor_match": self.successor_match,
            "successor_addresses": {
                "original": [hex(a) for a in self.successor_addresses[0]],
                "mutated": [hex(a) for a in self.successor_addresses[1]],
            },
        }

