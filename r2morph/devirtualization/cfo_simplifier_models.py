"""
Core models for the CFO simplifier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CFOPattern(Enum):
    """Types of control flow obfuscation patterns."""

    DISPATCHER_FLATTENING = "dispatcher_flattening"
    SWITCH_CASE_OBFUSCATION = "switch_case_obfuscation"
    INDIRECT_JUMPS = "indirect_jumps"
    OPAQUE_PREDICATES = "opaque_predicates"
    FAKE_CONTROL_FLOW = "fake_control_flow"
    EXCEPTION_BASED_FLOW = "exception_based_flow"


@dataclass
class ControlFlowBlock:
    """Represents a basic block in control flow analysis."""

    address: int
    instructions: list[dict[str, Any]] = field(default_factory=list)
    predecessors: set[int] = field(default_factory=set)
    successors: set[int] = field(default_factory=set)
    is_dispatcher: bool = False
    dispatcher_state: int | None = None
    original_target: int | None = None


@dataclass
class DispatcherInfo:
    """Information about a control flow dispatcher."""

    dispatcher_address: int
    state_variable: str
    dispatch_table: dict[int, int] = field(default_factory=dict)
    entry_blocks: set[int] = field(default_factory=set)
    exit_blocks: set[int] = field(default_factory=set)
    pattern_confidence: float = 0.0


@dataclass
class CFOSimplificationResult:
    """Result of control flow obfuscation simplification."""

    success: bool
    patterns_detected: list[CFOPattern] = field(default_factory=list)
    simplified_blocks: dict[int, ControlFlowBlock] = field(default_factory=dict)
    original_complexity: int = 0
    simplified_complexity: int = 0
    dispatcher_info: list[DispatcherInfo] = field(default_factory=list)
    removed_opcodes: list[str] = field(default_factory=list)
    execution_time: float = 0.0
    warnings: list[str] = field(default_factory=list)
