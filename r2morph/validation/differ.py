"""
Binary diffing for mutation validation visualization.

Provides structured comparison between original and mutated binaries
to visualize changes and verify correctness.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


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


class BinaryDiffer:
    """
    Compare original and mutated binaries to produce structured diffs.

    Provides:
    - Section-level comparison
    - Function-level comparison
    - Byte-level diff with context
    - Disassembly comparison
    """

    def __init__(self, original: Binary, mutated: Binary, context_bytes: int = 8) -> None:
        """
        Initialize binary differ.

        Args:
            original: Original binary
            mutated: Mutated binary
            context_bytes: Bytes of context to include in diffs
        """
        self.original = original
        self.mutated = mutated
        self.context_bytes = context_bytes

    def compare(self) -> DiffReport:
        """
        Perform full comparison between binaries.

        Returns:
            DiffReport with all differences
        """
        diffs: list[BinaryDiff] = []

        diffs.extend(self._compare_sections())
        diffs.extend(self._compare_functions())
        diffs.extend(self._compare_symbols())
        diffs.extend(self._compare_header())

        report = DiffReport(
            original_binary=str(self.original.path) if self.original.path else "memory",
            mutated_binary=str(self.mutated.path) if self.mutated.path else "memory",
            diffs=diffs,
        )
        report._compute_summary()

        return report

    def _compare_sections(self) -> list[BinaryDiff]:
        """Compare sections between binaries."""
        diffs: list[BinaryDiff] = []

        try:
            orig_sections = self.original.get_sections()
            mut_sections = self.mutated.get_sections()
        except Exception:
            return diffs

        orig_names = {s.get("name", ""): s for s in orig_sections}
        mut_names = {s.get("name", ""): s for s in mut_sections}

        for name, section in orig_names.items():
            if name not in mut_names:
                diffs.append(
                    BinaryDiff(
                        original_path=str(self.original.path) if self.original.path else "",
                        mutated_path=str(self.mutated.path) if self.mutated.path else "",
                        diff_type=DiffType.SECTION_REMOVED,
                        severity=ChangeSeverity.HIGH,
                        description=f"Section '{name}' removed",
                    )
                )

        for name, section in mut_names.items():
            if name not in orig_names:
                diffs.append(
                    BinaryDiff(
                        original_path=str(self.original.path) if self.original.path else "",
                        mutated_path=str(self.mutated.path) if self.mutated.path else "",
                        diff_type=DiffType.SECTION_ADDED,
                        severity=ChangeSeverity.MEDIUM,
                        description=f"Section '{name}' added",
                    )
                )

        for name in set(orig_names.keys()) & set(mut_names.keys()):
            orig = orig_names[name]
            mut = mut_names[name]

            orig_addr = orig.get("addr", orig.get("virtual_address", 0))
            mut_addr = mut.get("addr", mut.get("virtual_address", 0))
            orig_size = orig.get("size", orig.get("virtual_size", 0))
            mut_size = mut.get("size", mut.get("virtual_size", 0))

            if orig_addr != mut_addr or orig_size != mut_size:
                section_diff = SectionDiff(
                    name=name,
                    original_address=orig_addr,
                    mutated_address=mut_addr,
                    original_size=orig_size,
                    mutated_size=mut_size,
                    original_permissions=orig.get("perm", ""),
                    mutated_permissions=mut.get("perm", ""),
                )

                byte_diffs = self._compare_section_bytes(name, orig, mut)
                section_diff.byte_diffs = byte_diffs

                severity = ChangeSeverity.HIGH if len(byte_diffs) > 10 else ChangeSeverity.MEDIUM

                diffs.append(
                    BinaryDiff(
                        original_path=str(self.original.path) if self.original.path else "",
                        mutated_path=str(self.mutated.path) if self.mutated.path else "",
                        diff_type=DiffType.SECTION_MODIFIED,
                        severity=severity,
                        description=f"Section '{name}' modified",
                        section_diffs=[section_diff],
                        byte_diff_count=len(byte_diffs),
                    )
                )

        return diffs

    def _compare_section_bytes(self, name: str, orig_section: dict, mut_section: dict) -> list[ByteDiff]:
        """Compare bytes within a section."""
        diffs: list[ByteDiff] = []

        orig_addr = orig_section.get("addr", orig_section.get("virtual_address", 0))
        orig_size = orig_section.get("size", orig_section.get("virtual_size", 0))
        mut_size = mut_section.get("size", mut_section.get("virtual_size", 0))

        try:
            orig_data = self.original.read_bytes(orig_addr, min(orig_size, mut_size, 4096))
            mut_data = self.mutated.read_bytes(
                mut_section.get("addr", mut_section.get("virtual_address", 0)), min(orig_size, mut_size, 4096)
            )
        except Exception:
            return diffs

        min_len = min(len(orig_data), len(mut_data))

        for i in range(min_len):
            if orig_data[i] != mut_data[i]:
                context_start = max(0, i - self.context_bytes)
                context_end = min(min_len, i + self.context_bytes + 1)

                context_before = orig_data[context_start:i]
                context_after = orig_data[i + 1 : context_end]

                diffs.append(
                    ByteDiff(
                        offset=orig_addr + i,
                        original=bytes([orig_data[i]]),
                        mutated=bytes([mut_data[i]]),
                        context_before=context_before,
                        context_after=context_after,
                    )
                )

        return diffs

    def _compare_functions(self) -> list[BinaryDiff]:
        """Compare functions between binaries."""
        diffs: list[BinaryDiff] = []

        try:
            orig_funcs = self.original.get_functions()
            mut_funcs = self.mutated.get_functions()
        except Exception:
            return diffs

        orig_addrs = {f.get("offset", f.get("addr", 0)): f for f in orig_funcs}
        mut_addrs = {f.get("offset", f.get("addr", 0)): f for f in mut_funcs}

        for addr, func in orig_addrs.items():
            if addr not in mut_addrs:
                diffs.append(
                    BinaryDiff(
                        original_path=str(self.original.path) if self.original.path else "",
                        mutated_path=str(self.mutated.path) if self.mutated.path else "",
                        diff_type=DiffType.FUNCTION_REMOVED,
                        severity=ChangeSeverity.HIGH,
                        description=f"Function at 0x{addr:x} removed",
                    )
                )

        for addr, func in mut_addrs.items():
            if addr not in orig_addrs:
                diffs.append(
                    BinaryDiff(
                        original_path=str(self.original.path) if self.original.path else "",
                        mutated_path=str(self.mutated.path) if self.mutated.path else "",
                        diff_type=DiffType.FUNCTION_ADDED,
                        severity=ChangeSeverity.MEDIUM,
                        description=f"Function at 0x{addr:x} added",
                    )
                )

        for addr in set(orig_addrs.keys()) & set(mut_addrs.keys()):
            orig_func = orig_addrs[addr]
            mut_func = mut_addrs[addr]

            orig_size = orig_func.get("size", 0)
            mut_size = mut_func.get("size", 0)

            if orig_size != mut_size:
                func_diff = FunctionDiff(
                    name=orig_func.get("name", f"func_{addr:x}"),
                    address=addr,
                    original_size=orig_size,
                    mutated_size=mut_size,
                )
                diffs.append(
                    BinaryDiff(
                        original_path=str(self.original.path) if self.original.path else "",
                        mutated_path=str(self.mutated.path) if self.mutated.path else "",
                        diff_type=DiffType.FUNCTION_MODIFIED,
                        severity=ChangeSeverity.LOW,
                        description=f"Function {func_diff.name} size changed",
                        function_diffs=[func_diff],
                    )
                )

        return diffs

    def _compare_symbols(self) -> list[BinaryDiff]:
        """Compare symbols between binaries."""
        diffs: list[BinaryDiff] = []

        return diffs

    def _compare_header(self) -> list[BinaryDiff]:
        """Compare binary headers."""
        diffs: list[BinaryDiff] = []

        try:
            orig_arch = self.original.get_arch_info()
            mut_arch = self.mutated.get_arch_info()
        except Exception:
            return diffs

        if orig_arch.get("arch") != mut_arch.get("arch"):
            diffs.append(
                BinaryDiff(
                    original_path=str(self.original.path) if self.original.path else "",
                    mutated_path=str(self.mutated.path) if self.mutated.path else "",
                    diff_type=DiffType.HEADER_MODIFIED,
                    severity=ChangeSeverity.CRITICAL,
                    description=f"Architecture changed from {orig_arch.get('arch')} to {mut_arch.get('arch')}",
                )
            )

        if orig_arch.get("bits") != mut_arch.get("bits"):
            diffs.append(
                BinaryDiff(
                    original_path=str(self.original.path) if self.original.path else "",
                    mutated_path=str(self.mutated.path) if self.mutated.path else "",
                    diff_type=DiffType.HEADER_MODIFIED,
                    severity=ChangeSeverity.CRITICAL,
                    description=f"Bits changed from {orig_arch.get('bits')} to {mut_arch.get('bits')}",
                )
            )

        return diffs

    def get_function_diff(self, address: int) -> FunctionDiff | None:
        """
        Get detailed diff for a specific function.

        Args:
            address: Function address

        Returns:
            FunctionDiff or None
        """
        try:
            orig_disasm_first = self.original.get_function_disasm(address)
            mut_disasm_first = self.mutated.get_function_disasm(address)
        except Exception:
            return None

        if not orig_disasm_first or not mut_disasm_first:
            return None

        orig_size = orig_disasm_first[-1].get("offset", 0) + orig_disasm_first[-1].get("size", 0) - address
        mut_size = mut_disasm_first[-1].get("offset", 0) + mut_disasm_first[-1].get("size", 0) - address

        try:
            orig_data = self.original.read_bytes(address, max(orig_size, 1))
            mut_data = self.mutated.read_bytes(address, max(mut_size, 1))
        except Exception:
            return None

        if orig_data is None or mut_data is None:
            return None

        try:
            orig_disasm = self.original.get_function_disasm(address)
            mut_disasm = self.mutated.get_function_disasm(address)
        except Exception:
            orig_disasm = []
            mut_disasm = []

        byte_diffs = self._compute_byte_diffs(orig_data, mut_data, address)

        disasm_diff = []
        max_insn = max(len(orig_disasm), len(mut_disasm))
        for i in range(max_insn):
            orig_insn = orig_disasm[i] if i < len(orig_disasm) else None
            mut_insn = mut_disasm[i] if i < len(mut_disasm) else None

            orig_str = orig_insn.get("disasm", "") if orig_insn else ""
            mut_str = mut_insn.get("disasm", "") if mut_insn else ""

            if orig_str != mut_str:
                disasm_diff.append((address + i, orig_str, mut_str))

        func_name = f"func_{address:x}"
        try:
            funcs = self.mutated.get_functions()
            for f in funcs:
                if f.get("offset", f.get("addr", 0)) == address:
                    func_name = f.get("name", func_name)
                    break
        except Exception:
            pass

        return FunctionDiff(
            name=func_name,
            address=address,
            original_size=len(orig_data),
            mutated_size=len(mut_data),
            original_bytes=orig_data,
            mutated_bytes=mut_data,
            byte_diffs=byte_diffs,
            disassembly_diff=disasm_diff,
        )

    def _compute_byte_diffs(self, orig: bytes, mut: bytes, base_addr: int) -> list[ByteDiff]:
        """Compute byte-level differences."""
        diffs: list[ByteDiff] = []
        min_len = min(len(orig), len(mut))

        for i in range(min_len):
            if orig[i] != mut[i]:
                context_start = max(0, i - self.context_bytes)
                context_end = min(min_len, i + self.context_bytes + 1)

                diffs.append(
                    ByteDiff(
                        offset=base_addr + i,
                        original=bytes([orig[i]]),
                        mutated=bytes([mut[i]]),
                        context_before=orig[context_start:i],
                        context_after=orig[i + 1 : context_end],
                    )
                )

        if len(orig) != len(mut):
            start = min_len
            diffs.append(
                ByteDiff(
                    offset=base_addr + start,
                    original=orig[start:] if start < len(orig) else b"",
                    mutated=mut[start:] if start < len(mut) else b"",
                )
            )

        return diffs


def compare_binaries(original: Binary, mutated: Binary) -> DiffReport:
    """
    Convenience function for binary comparison.

    Args:
        original: Original binary
        mutated: Mutated binary

    Returns:
        DiffReport
    """
    differ = BinaryDiffer(original, mutated)
    return differ.compare()
