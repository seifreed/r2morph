"""Pure helpers for diff rendering in the TUI."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class DisasmDiffRow:
    index: int
    original: str
    mutated: str
    status: str


def build_disasm_diff_rows(
    original_lines: Sequence[str] | None,
    mutated_lines: Sequence[str] | None,
    *,
    limit: int,
    display_width: int,
) -> list[DisasmDiffRow]:
    """Build a bounded set of diff rows for rendering."""
    orig_lines = list(original_lines or [])
    mut_lines = list(mutated_lines or [])
    max_lines = max(len(orig_lines), len(mut_lines), 1)
    rows: list[DisasmDiffRow] = []

    for i in range(min(max_lines, limit)):
        orig_line = orig_lines[i] if i < len(orig_lines) else ""
        mut_line = mut_lines[i] if i < len(mut_lines) else ""

        if orig_line == mut_line:
            status = "same"
        elif not orig_line:
            status = "added"
        elif not mut_line:
            status = "removed"
        else:
            status = "changed"

        rows.append(
            DisasmDiffRow(
                index=i + 1,
                original=orig_line[:display_width] if orig_line else "",
                mutated=mut_line[:display_width] if mut_line else "",
                status=status,
            )
        )

    return rows


def count_disasm_changed_lines(
    original_lines: Sequence[str] | None,
    mutated_lines: Sequence[str] | None,
) -> int:
    """Count line-level changes between original and mutated disassembly."""
    orig_lines = list(original_lines or [])
    mut_lines = list(mutated_lines or [])
    max_lines = max(len(orig_lines), len(mut_lines), 1)

    return sum(
        1
        for i in range(max_lines)
        if (i < len(orig_lines) and i < len(mut_lines) and orig_lines[i] != mut_lines[i])
        or (i >= len(orig_lines) and i < len(mut_lines))
        or (i < len(orig_lines) and i >= len(mut_lines))
    )


def count_byte_differences(
    original_bytes: bytes | None,
    mutated_bytes: bytes | None,
) -> tuple[int, int]:
    """Count differing byte positions and total compared length."""
    orig_bytes = original_bytes or b""
    mut_bytes = mutated_bytes or b""
    total = max(len(orig_bytes), len(mut_bytes))
    diff_count = 0

    for i in range(total):
        orig_byte = orig_bytes[i] if i < len(orig_bytes) else None
        mut_byte = mut_bytes[i] if i < len(mut_bytes) else None
        if orig_byte != mut_byte:
            diff_count += 1

    return diff_count, total
