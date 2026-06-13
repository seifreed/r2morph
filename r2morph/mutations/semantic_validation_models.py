"""Shared data models for post-mutation semantic validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ValidationSeverity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationIssue:
    code: str
    severity: ValidationSeverity
    message: str
    address: int = 0
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == ValidationSeverity.ERROR]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == ValidationSeverity.WARNING]

    def add_error(self, code: str, message: str, address: int = 0, **details: Any) -> None:
        self.issues.append(ValidationIssue(code, ValidationSeverity.ERROR, message, address, details))
        self.valid = False

    def add_warning(self, code: str, message: str, address: int = 0, **details: Any) -> None:
        self.issues.append(ValidationIssue(code, ValidationSeverity.WARNING, message, address, details))


__all__ = [
    "ValidationSeverity",
    "ValidationIssue",
    "ValidationResult",
]
