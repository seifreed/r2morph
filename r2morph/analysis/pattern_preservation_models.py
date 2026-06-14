"""Pure models for pattern preservation analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PatternType(Enum):
    EXCEPTION_HANDLER = "exception_handler"
    LANDING_PAD = "landing_pad"
    JUMP_TABLE = "jump_table"
    JUMP_TABLE_ENTRY = "jump_table_entry"
    SWITCH_DISPATCHER = "switch_dispatcher"
    VIRTUAL_DISPATCHER = "virtual_dispatcher"
    PLT_THUNK = "plt_thunk"
    GOT_ENTRY = "got_entry"
    TAIL_CALL = "tail_call"
    INDIRECT_JUMP = "indirect_jump"


class Criticality(Enum):
    PRESERVE = "preserve"
    AVOID = "avoid"
    CAUTION = "caution"


@dataclass
class PreservedPattern:
    type: PatternType
    start_address: int
    end_address: int
    criticality: Criticality = Criticality.PRESERVE
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return self.end_address - self.start_address

    def contains(self, address: int) -> bool:
        return self.start_address <= address < self.end_address

    def overlaps(self, start: int, end: int) -> bool:
        return self.start_address < end and start < self.end_address

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "start_address": f"0x{self.start_address:x}",
            "end_address": f"0x{self.end_address:x}",
            "size": self.size,
            "criticality": self.criticality.value,
            "source": self.source,
        }


@dataclass
class ExclusionZone:
    start_address: int
    end_address: int
    pattern_type: PatternType
    reason: str = ""
    radius: int = 0

    @property
    def expanded_start(self) -> int:
        return max(0, self.start_address - self.radius)

    @property
    def expanded_end(self) -> int:
        return self.end_address + self.radius

    def contains(self, address: int) -> bool:
        return self.expanded_start <= address < self.expanded_end

    def to_dict(self) -> dict[str, Any]:
        return {
            "start_address": f"0x{self.expanded_start:x}",
            "end_address": f"0x{self.expanded_end:x}",
            "pattern_type": self.pattern_type.value,
            "reason": self.reason,
            "radius": self.radius,
        }
