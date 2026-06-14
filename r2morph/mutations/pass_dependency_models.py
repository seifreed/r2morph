"""Pure dependency models for mutation pass ordering."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class DependencyType(Enum):
    """Type of pass dependency."""

    REQUIRES = "requires"
    CONFLICTS_WITH = "conflicts_with"
    RECOMMENDS = "recommends"
    REQUIRES_ABSENCE = "requires_absence"


@dataclass
class PassDependency:
    """
    Represents a dependency between two mutation passes.

    Attributes:
        source_pass: Name of the pass that has the dependency
        target_pass: Name of the pass that is depended on
        dep_type: Type of the dependency
        reason: Human-readable reason for the dependency
        optional: Whether this dependency is optional
    """

    source_pass: str
    target_pass: str
    dep_type: DependencyType
    reason: str = ""
    optional: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_pass": self.source_pass,
            "target_pass": self.target_pass,
            "dep_type": self.dep_type.value,
            "reason": self.reason,
            "optional": self.optional,
        }

    def __str__(self) -> str:
        if self.dep_type == DependencyType.REQUIRES:
            return f"{self.source_pass} requires {self.target_pass}"
        if self.dep_type == DependencyType.CONFLICTS_WITH:
            return f"{self.source_pass} conflicts with {self.target_pass}"
        if self.dep_type == DependencyType.RECOMMENDS:
            return f"{self.source_pass} recommends {self.target_pass}"
        if self.dep_type == DependencyType.REQUIRES_ABSENCE:
            return f"{self.source_pass} requires absence of {self.target_pass}"
        return f"{self.source_pass} -> {self.target_pass}"


@dataclass
class DependencyViolation:
    """Represents a dependency violation in a pipeline."""

    source_pass: str
    target_pass: str
    violation_type: str
    message: str
    severity: str = "error"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_pass": self.source_pass,
            "target_pass": self.target_pass,
            "violation_type": self.violation_type,
            "message": self.message,
            "severity": self.severity,
        }
