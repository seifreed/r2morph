"""Shared data models for the polymorphic engine."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class EngineState(Enum):
    """States for the polymorphic engine."""

    INIT = auto()
    SUBSTITUTED = auto()
    DEAD_CODE_INJECTED = auto()
    REORDERED = auto()
    FLATTENED = auto()
    OBFUSCATED = auto()
    VIRTUALIZED = auto()
    STRING_OBFUSCATED = auto()
    MOBILIZED = auto()
    OUTLINED = auto()
    FINAL = auto()


@dataclass
class StateTransition:
    """Represents a state transition in the engine."""

    from_state: EngineState
    to_state: EngineState
    mutation_name: str
    condition: Callable[[dict[str, Any]], bool] | None = None
    probability: float = 1.0


@dataclass
class MutationResult:
    """Result of a single mutation application."""

    name: str
    state_before: EngineState
    state_after: EngineState
    success: bool
    stats: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class EngineRunResult:
    """Result of complete engine run."""

    initial_state: EngineState
    final_state: EngineState
    iterations: int
    mutations_applied: list[MutationResult] = field(default_factory=list)
    final_stats: dict[str, Any] = field(default_factory=dict)
    converged: bool = False


__all__ = [
    "EngineState",
    "StateTransition",
    "MutationResult",
    "EngineRunResult",
]
