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


@dataclass
class ExceptionFrame:
    """Represents exception frame information."""

    function_start: int
    function_end: int
    personality: int | None = None
    lsda_address: int | None = None
    landing_pads: list[LandingPad] = field(default_factory=list)
