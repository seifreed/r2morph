"""Result models for pattern-based detection."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PatternMatchResult:
    """Result of pattern matching analysis."""

    anti_debug_detected: bool = False
    anti_debug_confidence: float = 0.0
    anti_debug_apis: list[str] = field(default_factory=list)
    anti_vm_detected: bool = False
    anti_vm_confidence: float = 0.0
    anti_vm_artifacts: list[str] = field(default_factory=list)
    string_encryption_detected: bool = False
    import_hiding_detected: bool = False
