"""Pure data models for the TUI."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TUIAction(str, Enum):
    SELECT_FUNCTIONS = "select_functions"
    SELECT_PASSES = "select_passes"
    PREVIEW_MUTATIONS = "preview_mutations"
    CONFIRM = "confirm"
    EXECUTE = "execute"
    CANCEL = "cancel"


@dataclass
class TUIMutation:
    address: int
    function: str | None
    pass_name: str
    original_bytes: bytes
    mutated_bytes: bytes
    description: str | None = None
    original_disasm: list[str] | None = None
    mutated_disasm: list[str] | None = None


@dataclass
class TUIFunction:
    address: int
    name: str
    size: int
    selected: bool = False


@dataclass
class TUIPass:
    name: str
    description: str
    is_stable: bool
    selected: bool = False
    configurable: bool = False
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class TUIResult:
    functions: list[TUIFunction]
    passes: list[TUIPass]
    confirmed: bool = False


@dataclass
class TUIProgress:
    total: int = 0
    current: int = 0
    message: str = ""
    status: str = "running"
