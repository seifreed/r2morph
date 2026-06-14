"""Result models for control flow detection."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ControlFlowAnalysisResult:
    """Result of control flow analysis."""

    cff_detected: bool = False
    cff_confidence: float = 0.0
    opaque_predicates_count: int = 0
    mba_expressions_count: int = 0
    vm_detected: bool = False
    vm_confidence: float = 0.0
    vm_handler_count: int = 0
    vm_indicators: list[str] = field(default_factory=list)
    metamorphic_detected: bool = False
    metamorphic_confidence: float = 0.0
    metamorphic_indicators: list[str] = field(default_factory=list)
    polymorphic_ratio: float = 0.0
