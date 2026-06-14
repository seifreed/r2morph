"""Pure data models for symbolic constraint solving."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ConstraintType(Enum):
    """Types of constraints in symbolic execution."""

    PATH_CONSTRAINT = "path"
    OPAQUE_PREDICATE = "opaque"
    MBA_EXPRESSION = "mba"
    SEMANTIC_EQUIVALENCE = "semantic"
    VM_HANDLER_DISPATCH = "vm_dispatch"


@dataclass
class SolverResult:
    """Result from constraint solving."""

    satisfiable: bool = False
    model: dict[str, Any] | None = None
    simplified_expression: str | None = None
    solving_time: float = 0.0
    solver_used: str = "unknown"
    confidence: float = 0.0


@dataclass
class MBAExpression:
    """Mixed Boolean Arithmetic expression representation."""

    expression: str
    variables: set[str] = field(default_factory=set)
    bit_width: int = 64
    complexity_score: float = 0.0
    simplified_form: str | None = None
