"""Data models for CFG integrity validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.analysis.pattern_preservation_models import PreservedPattern


class IntegrityStatus(Enum):
    VALID = "valid"
    BROKEN_EDGE = "broken_edge"
    UNREACHABLE = "unreachable"
    INVALID_TARGET = "invalid_target"
    EXCEPTION_FLOW = "exception_flow"
    JUMP_TABLE = "jump_table"
    PLT_THUNK = "plt_thunk"


@dataclass
class IntegrityViolation:
    status: IntegrityStatus
    address: int
    description: str
    severity: str = "error"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "address": f"0x{self.address:x}",
            "description": self.description,
            "severity": self.severity,
            "metadata": self.metadata,
        }


@dataclass
class IntegrityCheck:
    name: str
    description: str
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
        }


@dataclass
class IntegrityReport:
    valid: bool
    violations: list[IntegrityViolation] = field(default_factory=list)
    checks_run: list[IntegrityCheck] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "violations": [v.to_dict() for v in self.violations],
            "checks_run": [c.to_dict() for c in self.checks_run],
            "statistics": self.statistics,
        }


@dataclass
class CFGSnapshot:
    function_address: int
    blocks: dict[int, dict[str, Any]]
    edges: list[tuple[int, int, str]]
    entry_block: int | None = None
    exit_blocks: list[int] = field(default_factory=list)
    preserved_patterns: list[PreservedPattern] = field(default_factory=list)
