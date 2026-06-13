"""Diff report models for binary comparison."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class DiffType(Enum):
    """Type of binary difference."""

    SECTION_ADDED = "section_added"
    SECTION_REMOVED = "section_removed"
    SECTION_MODIFIED = "section_modified"
    FUNCTION_ADDED = "function_added"
    FUNCTION_REMOVED = "function_removed"
    FUNCTION_MODIFIED = "function_modified"
    BYTES_CHANGED = "bytes_changed"
    SYMBOL_ADDED = "symbol_added"
    SYMBOL_REMOVED = "symbol_removed"
    SYMBOL_MODIFIED = "symbol_modified"
    IMPORT_ADDED = "import_added"
    IMPORT_REMOVED = "import_removed"
    EXPORT_ADDED = "export_added"
    EXPORT_REMOVED = "export_removed"
    HEADER_MODIFIED = "header_modified"


class ChangeSeverity(Enum):
    """Severity level of a change."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ByteDiff:
    """Difference at byte level."""

    offset: int
    original: bytes
    mutated: bytes
    context_before: bytes = b""
    context_after: bytes = b""

    def to_dict(self) -> dict[str, Any]:
        return {
            "offset": hex(self.offset),
            "original": self.original.hex(),
            "mutated": self.mutated.hex(),
            "context_before": self.context_before.hex() if self.context_before else "",
            "context_after": self.context_after.hex() if self.context_after else "",
        }


@dataclass
class SectionDiff:
    """Difference at section level."""

    name: str
    original_address: int | None = None
    mutated_address: int | None = None
    original_size: int | None = None
    mutated_size: int | None = None
    original_permissions: str | None = None
    mutated_permissions: str | None = None
    byte_diffs: list[ByteDiff] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "original_address": hex(self.original_address) if self.original_address else None,
            "mutated_address": hex(self.mutated_address) if self.mutated_address else None,
            "original_size": self.original_size,
            "mutated_size": self.mutated_size,
            "original_permissions": self.original_permissions,
            "mutated_permissions": self.mutated_permissions,
            "byte_diffs": [bd.to_dict() for bd in self.byte_diffs],
        }


@dataclass
class FunctionDiff:
    """Difference at function level."""

    name: str
    address: int
    original_size: int | None = None
    mutated_size: int | None = None
    original_bytes: bytes | None = None
    mutated_bytes: bytes | None = None
    byte_diffs: list[ByteDiff] = field(default_factory=list)
    disassembly_diff: list[tuple[int, str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "address": hex(self.address),
            "original_size": self.original_size,
            "mutated_size": self.mutated_size,
            "byte_diff_count": len(self.byte_diffs),
            "disassembly_diff_count": len(self.disassembly_diff),
        }


@dataclass
class BinaryDiff:
    """Complete binary difference report."""

    original_path: str
    mutated_path: str
    diff_type: DiffType
    severity: ChangeSeverity
    description: str
    section_diffs: list[SectionDiff] = field(default_factory=list)
    function_diffs: list[FunctionDiff] = field(default_factory=list)
    byte_diff_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_path": self.original_path,
            "mutated_path": self.mutated_path,
            "diff_type": self.diff_type.value,
            "severity": self.severity.value,
            "description": self.description,
            "section_diffs": [sd.to_dict() for sd in self.section_diffs],
            "function_diffs": [fd.to_dict() for fd in self.function_diffs],
            "byte_diff_count": self.byte_diff_count,
            "metadata": self.metadata,
        }


@dataclass
class DiffReport:
    """Complete diff report with statistics."""

    original_binary: str
    mutated_binary: str
    diffs: list[BinaryDiff] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_binary": self.original_binary,
            "mutated_binary": self.mutated_binary,
            "diffs": [d.to_dict() for d in self.diffs],
            "summary": self.summary,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        import json

        return json.dumps(self.to_dict(), indent=indent)

    def write_report(self, path: Path) -> None:
        """Write report to file."""
        path.write_text(self.to_json())

    def get_changes_by_severity(self) -> dict[ChangeSeverity, list[BinaryDiff]]:
        """Group changes by severity."""
        result: dict[ChangeSeverity, list[BinaryDiff]] = {s: [] for s in ChangeSeverity}
        for diff in self.diffs:
            result[diff.severity].append(diff)
        return result

    def _compute_summary(self) -> None:
        """Compute summary statistics."""
        self.summary = {
            "total_changes": len(self.diffs),
            "by_severity": {s.value: len([d for d in self.diffs if d.severity == s]) for s in ChangeSeverity},
            "by_type": {t.value: len([d for d in self.diffs if d.diff_type == t]) for t in DiffType},
            "total_byte_diffs": sum(d.byte_diff_count for d in self.diffs),
            "sections_affected": len(set(sd.name for d in self.diffs for sd in d.section_diffs)),
            "functions_affected": len(set(fd.name for d in self.diffs for fd in d.function_diffs)),
        }


__all__ = [
    "DiffType",
    "ChangeSeverity",
    "ByteDiff",
    "SectionDiff",
    "FunctionDiff",
    "BinaryDiff",
    "DiffReport",
]
