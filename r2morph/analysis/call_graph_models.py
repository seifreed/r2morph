"""Shared call graph model types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CallType(Enum):
    """Type of call instruction."""

    DIRECT = "direct"
    INDIRECT = "indirect"
    TAIL = "tail"
    PLT = "plt"
    LIBRARY = "library"
    UNKNOWN = "unknown"


class RecursionType(Enum):
    """Type of recursion in call graph."""

    NONE = "none"
    DIRECT = "direct"
    MUTUAL = "mutual"


@dataclass
class CallNode:
    """
    Represents a function node in the call graph.

    Attributes:
        address: Function start address
        name: Function name (if available)
        size: Function size in bytes
        call_type: Type of function (user, library, plt)
        callers: Addresses of functions that call this function
        callees: Addresses of functions called by this function
        is_recursive: Whether this function is recursive
        recursion_depth: Maximum recursion depth if recursive
    """

    address: int
    name: str = ""
    size: int = 0
    call_type: CallType = CallType.DIRECT
    callers: list[int] = field(default_factory=list)
    callees: list[int] = field(default_factory=list)
    is_recursive: bool = False
    recursion_depth: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"<CallNode @ 0x{self.address:x} name={self.name} callers={len(self.callers)} callees={len(self.callees)}>"
        )

    def __hash__(self) -> int:
        return hash(self.address)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CallNode):
            return False
        return self.address == other.address

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "address": f"0x{self.address:x}",
            "name": self.name,
            "size": self.size,
            "call_type": self.call_type.value,
            "callers": [f"0x{a:x}" for a in self.callers],
            "callees": [f"0x{a:x}" for a in self.callees],
            "is_recursive": self.is_recursive,
            "recursion_depth": self.recursion_depth,
            "metadata": self.metadata,
        }


@dataclass
class CallEdge:
    """
    Represents an edge in the call graph.

    Attributes:
        caller: Address of calling function
        callee: Address of called function
        call_type: Type of call (direct, indirect, tail)
        call_site: Address where the call instruction occurs
        is_tail_call: Whether this is a tail call
    """

    caller: int
    callee: int
    call_type: CallType
    call_site: int = 0
    is_tail_call: bool = False

    def __repr__(self) -> str:
        return f"<CallEdge 0x{self.caller:x} -> 0x{self.callee:x} ({self.call_type.value})>"

    def __hash__(self) -> int:
        return hash((self.caller, self.callee, self.call_site))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "caller": f"0x{self.caller:x}",
            "callee": f"0x{self.callee:x}",
            "call_type": self.call_type.value,
            "call_site": f"0x{self.call_site:x}",
            "is_tail_call": self.is_tail_call,
        }


@dataclass
class _DepthFrame:
    """One in-progress get_depth() recursion, simulated on an explicit stack."""

    callees: list[int]
    idx: int = 0
    best: int = 0


@dataclass
class _PathFrame:
    """One in-progress find_call_path() recursion, simulated on a stack."""

    callees: list[int]
    idx: int = 0


@dataclass
class _SccFrame:
    """One in-progress strongconnect() recursion, simulated on a stack."""

    node: int
    callees: list[int]
    idx: int = 0


@dataclass
class _RecursionFrame:
    """One in-progress _detect_recursion() dfs(), simulated on a stack."""

    node_addr: int
    callees: list[int]
    idx: int = 0


__all__ = [
    "CallEdge",
    "CallNode",
    "CallType",
    "RecursionType",
]
