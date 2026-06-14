"""
Binary diffing for mutation validation visualization.

Provides structured comparison between original and mutated binaries
to visualize changes and verify correctness.
"""

from __future__ import annotations

import logging

from r2morph.core.binary import Binary
from r2morph.validation.differ_comparison import build_diff_report
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
        return build_diff_report(self.original, self.mutated, self.context_bytes)

    def _compare_sections(self) -> list[BinaryDiff]:
        """Compare sections between binaries."""
        from r2morph.validation.differ_comparison import compare_sections

        return compare_sections(self.original, self.mutated, self.context_bytes)

    def _compare_section_bytes(self, orig_section: dict, mut_section: dict) -> list[ByteDiff]:
        """Compare bytes within a section."""
        return compare_section_bytes(self.original, self.mutated, orig_section, mut_section, self.context_bytes)

    def _compare_functions(self) -> list[BinaryDiff]:
        """Compare functions between binaries."""
        from r2morph.validation.differ_comparison import compare_functions

        return compare_functions(self.original, self.mutated)

    def _compare_symbols(self) -> list[BinaryDiff]:
        """Compare symbols between binaries."""
        from r2morph.validation.differ_comparison import compare_symbols

        return compare_symbols(self.original, self.mutated)

    def _compare_header(self) -> list[BinaryDiff]:
        """Compare binary headers."""
        from r2morph.validation.differ_comparison import compare_header

        return compare_header(self.original, self.mutated)

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
