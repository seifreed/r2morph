"""Switch table model types used by the analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class JumpTableType(Enum):
    """Type of jump table."""

    DIRECT = "direct"
    INDIRECT = "indirect"
    COMPACT = "compact"
    EXPANDED = "expanded"
    PLT_GOT = "plt_got"


@dataclass
class JumpTableEntry:
    """Represents a single entry in a jump table."""

    index: int
    target_address: int
    case_value: int | None = None
    is_default: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class JumpTable:
    """
    Represents a complete jump table.

    Jump tables are used for switch statements and computed gotos.
    """

    table_address: int
    table_type: JumpTableType
    entries: list[JumpTableEntry] = field(default_factory=list)
    base_register: str | None = None
    scale: int = 4
    offset: int = 0
    default_case: int | None = None
    bounds_check_register: str | None = None
    bounds_check_address: int | None = None
    function_address: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def case_count(self) -> int:
        """Number of cases in the table."""
        return len([e for e in self.entries if not e.is_default])

    @property
    def unique_targets(self) -> list[int]:
        """Unique target addresses in the table."""
        return sorted(set(e.target_address for e in self.entries))

    @property
    def is_dense(self) -> bool:
        """Check if case values are dense (no gaps)."""
        case_values = sorted(e.case_value for e in self.entries if e.case_value is not None)
        if len(case_values) < 2:
            return True
        return case_values[-1] - case_values[0] + 1 == len(case_values)


@dataclass
class IndirectJump:
    """
    Represents an indirect jump instruction.

    Indirect jumps are used for:
    - Switch statements (via jump tables)
    - Tail calls
    - Virtual function dispatch
    - PLT/GOT thunks
    """

    address: int
    instruction: str
    jump_type: str
    base_register: str | None = None
    index_register: str | None = None
    scale: int = 1
    displacement: int = 0
    table_address: int | None = None
    target_candidates: list[int] = field(default_factory=list)
    function_address: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
