"""Validation manager data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ValidationIssue:
    """Represents a validation failure or warning."""

    validator: str
    message: str
    address_range: tuple[int, int] | None = None
    severity: str = "error"
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dict."""
        payload = asdict(self)
        if self.address_range is not None:
            payload["address_range"] = [self.address_range[0], self.address_range[1]]
        return payload


@dataclass
class ValidationOutcome:
    """Result of a validation run."""

    validator_type: str
    passed: bool
    scope: str
    issues: list[ValidationIssue] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dict."""
        return {
            "validator_type": self.validator_type,
            "passed": self.passed,
            "scope": self.scope,
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": dict(self.metadata),
        }
