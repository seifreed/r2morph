"""Invariant data models."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class InvariantType(Enum):
    """Types of code invariants."""

    STACK_BALANCE = "stack_balance"
    REGISTER_PRESERVATION = "reg_preserve"
    CALLING_CONVENTION = "call_conv"
    RETURN_VALUE = "return_value"
    CONTROL_FLOW = "control_flow"
    MEMORY_SAFETY = "memory_safety"


@dataclass
class Invariant:
    """Represents a code invariant that must be preserved."""

    invariant_type: InvariantType
    description: str
    location: int
    details: dict[str, Any]

    def __repr__(self) -> str:
        return f"<Invariant {self.invariant_type.value} @ 0x{self.location:x}: {self.description}>"
