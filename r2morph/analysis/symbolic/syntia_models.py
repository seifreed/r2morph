"""Pure models for Syntia semantic learning integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SemanticComplexity(Enum):
    """Complexity levels for semantic learning."""

    SIMPLE = "simple"  # Basic arithmetic/logic operations
    MEDIUM = "medium"  # Mixed operations with some obfuscation
    COMPLEX = "complex"  # Heavy obfuscation, VM handlers
    UNKNOWN = "unknown"  # Cannot determine complexity


@dataclass
class InstructionSemantics:
    """Learned semantics for an instruction or instruction sequence."""

    address: int
    instruction_bytes: bytes
    disassembly: str
    learned_semantics: str | None = None
    semantic_formula: str | None = None
    input_variables: set[str] = field(default_factory=set)
    output_variables: set[str] = field(default_factory=set)
    complexity: SemanticComplexity = SemanticComplexity.UNKNOWN
    confidence: float = 0.0
    learning_time: float = 0.0


@dataclass
class VMHandlerSemantics:
    """Semantics for a virtual machine handler."""

    handler_id: int
    entry_address: int
    handler_type: str  # e.g., "arithmetic", "branch", "memory"
    instruction_semantics: list[InstructionSemantics] = field(default_factory=list)
    overall_semantic_formula: str | None = None
    equivalent_native_code: str | None = None
    confidence: float = 0.0
