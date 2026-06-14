"""Pure models for the binary rewriter."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class BinaryFormat(Enum):
    """Supported binary formats."""

    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    UNKNOWN = "unknown"


class RewriteOperation(Enum):
    """Types of rewrite operations."""

    INSTRUCTION_REPLACE = "instruction_replace"
    INSTRUCTION_INSERT = "instruction_insert"
    INSTRUCTION_DELETE = "instruction_delete"
    BLOCK_REPLACE = "block_replace"
    FUNCTION_REPLACE = "function_replace"
    CODE_CAVE_INJECT = "code_cave_inject"


@dataclass
class CodePatch:
    """Represents a code patch to be applied."""

    address: int
    operation: RewriteOperation
    original_bytes: bytes
    new_bytes: bytes
    original_instructions: list[str] = field(default_factory=list)
    new_instructions: list[str] = field(default_factory=list)
    size_change: int = 0
    dependencies: list[int] = field(default_factory=list)


@dataclass
class RelocationEntry:
    """Represents a relocation entry."""

    address: int
    target: int
    reloc_type: str
    symbol: str | None = None
    addend: int = 0


@dataclass
class RewriteResult:
    """Result of binary rewriting operation."""

    success: bool
    output_path: str
    patches_applied: int = 0
    relocations_updated: int = 0
    size_change: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    execution_time: float = 0.0
    integrity_checks: dict[str, bool] = field(default_factory=dict)
