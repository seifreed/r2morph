"""Models for extended semantic validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ValidationResult:
    """Result of validation with extended metadata."""

    is_valid: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
