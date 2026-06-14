"""
Core models for virtual machine handler analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class VMHandlerType(Enum):
    """Types of VM handlers."""

    ARITHMETIC = "arithmetic"
    LOGICAL = "logical"
    MEMORY = "memory"
    STACK = "stack"
    BRANCH = "branch"
    CALL = "call"
    COMPARE = "compare"
    MOVE = "move"
    NOP = "nop"
    DISPATCHER = "dispatcher"
    UNKNOWN = "unknown"


@dataclass
class VMHandler:
    """Represents a virtual machine handler."""

    handler_id: int
    entry_address: int
    size: int
    handler_type: VMHandlerType = VMHandlerType.UNKNOWN
    instructions: list[dict[str, Any]] = field(default_factory=list)
    semantic_signature: str | None = None
    equivalent_x86: str | None = None
    confidence: float = 0.0
    analysis_notes: list[str] = field(default_factory=list)


@dataclass
class VMArchitecture:
    """Represents the overall VM architecture."""

    dispatcher_address: int
    handlers: dict[int, VMHandler] = field(default_factory=dict)
    handler_table_address: int | None = None
    vm_registers: list[str] = field(default_factory=list)
    vm_stack_address: int | None = None
    bytecode_address: int | None = None
    vm_context_size: int = 0
