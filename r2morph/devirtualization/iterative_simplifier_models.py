"""Pure models for iterative simplification."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SimplificationStrategy(Enum):
    """Different simplification strategies."""

    CONSERVATIVE = "conservative"
    AGGRESSIVE = "aggressive"
    ADAPTIVE = "adaptive"
    TARGETED = "targeted"


class SimplificationPhase(Enum):
    """Phases of the simplification process."""

    ANALYSIS = "analysis"
    PREPROCESSING = "preprocessing"
    CFO_REMOVAL = "cfo_removal"
    MBA_SIMPLIFICATION = "mba_simplification"
    VM_DEVIRTUALIZATION = "vm_devirtualization"
    OPTIMIZATION = "optimization"
    VALIDATION = "validation"


@dataclass
class SimplificationMetrics:
    """Metrics for tracking simplification progress."""

    iteration: int = 0
    total_instructions: int = 0
    removed_instructions: int = 0
    simplified_expressions: int = 0
    resolved_jumps: int = 0
    eliminated_predicates: int = 0
    devirtualized_handlers: int = 0
    complexity_reduction: float = 0.0
    execution_time: float = 0.0
    memory_usage: int = 0


@dataclass
class SimplificationResult:
    """Result of iterative simplification."""

    success: bool
    strategy_used: SimplificationStrategy
    phases_completed: list[SimplificationPhase] = field(default_factory=list)
    metrics: SimplificationMetrics = field(default_factory=SimplificationMetrics)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    intermediate_results: dict[str, Any] = field(default_factory=dict)
    final_binary: bytes | None = None


class SimplificationPass(ABC):
    """Abstract base class for simplification passes."""

    @abstractmethod
    def apply(self, binary: Any, context: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        """Apply the simplification pass."""

    @abstractmethod
    def get_name(self) -> str:
        """Get the name of this pass."""
