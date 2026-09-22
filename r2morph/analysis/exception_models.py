"""Shared model types for exception analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ExceptionAction(Enum):
    """Type of exception handling action."""

    CATCH = "catch"
    FILTER = "filter"
    FINALLY = "finally"
    CLEANUP = "cleanup"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class LsdaTemplate:
    """Action/type-table bytes reusable by a remapped LSDA call-site table."""

    landing_pad_encoding: int
    type_encoding: int
    type_table_offset: int | None
    action_table_offset: int
    action_and_type_bytes: bytes
    call_site_encoding: int = 0x0B
    type_table_delta: int | None = None


@dataclass
class LandingPad:
    """Represents a landing pad for exception handling."""

    address: int
    size: int
    action: ExceptionAction
    catch_type: str | None = None
    parent_try: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExceptionTableEntry:
    """Represents an entry in the exception handling table."""

    start_address: int
    end_address: int
    landing_pad: int | None
    action: ExceptionAction
    filter_address: int | None = None
    catch_type: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LsdaCallSite:
    """One decoded LSDA call-site row, including rows without a landing pad."""

    start_address: int
    end_address: int
    landing_pad: int
    action_index: int


@dataclass
class ExceptionFrame:
    """Represents exception frame information."""

    function_start: int
    function_end: int
    personality: int | None = None
    lsda_address: int | None = None
    lsda_template: LsdaTemplate | None = None
    landing_pads: list[LandingPad] = field(default_factory=list)
    lsda_call_sites: list[LsdaCallSite] = field(default_factory=list)
