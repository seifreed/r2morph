"""
Binary diffing for mutation validation visualization.

Provides structured comparison between original and mutated binaries
to visualize changes and verify correctness.
"""

from __future__ import annotations

import logging

from r2morph.core.binary import Binary
from r2morph.validation.differ_helpers import compare_section_bytes, compute_byte_diffs
from r2morph.validation.differ_models import (
    BinaryDiff,
    ByteDiff,
    ChangeSeverity,
    DiffReport,
    DiffType,
    FunctionDiff,
    SectionDiff,
)

logger = logging.getLogger(__name__)


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

        for name in orig_names:
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

        for name in mut_names:
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

                byte_diffs = self._compare_section_bytes(orig, mut)
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

    def _compare_section_bytes(self, orig_section: dict, mut_section: dict) -> list[ByteDiff]:
        """Compare bytes within a section."""
        return compare_section_bytes(self.original, self.mutated, orig_section, mut_section, self.context_bytes)

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

        for addr in orig_addrs:
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

        for addr in mut_addrs:
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
        except (AttributeError, TypeError, RuntimeError) as exc:
            logger.debug("Could not resolve function name for 0x%x; using default label: %s", address, exc)

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
        return compute_byte_diffs(orig, mut, base_addr, self.context_bytes)


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


__all__ = [
    "DiffType",
    "ChangeSeverity",
    "ByteDiff",
    "SectionDiff",
    "FunctionDiff",
    "BinaryDiff",
    "DiffReport",
    "BinaryDiffer",
    "compare_binaries",
]
