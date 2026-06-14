from __future__ import annotations

from r2morph.tui_diff_helpers import (
    build_disasm_diff_rows,
    count_byte_differences,
    count_disasm_changed_lines,
)


def test_disasm_diff_helpers_compute_rows_and_counts() -> None:
    rows = build_disasm_diff_rows(
        ["mov eax, ebx", "ret"],
        ["mov eax, ecx", "ret", "nop"],
        limit=16,
        display_width=12,
    )

    assert [(row.index, row.status) for row in rows] == [(1, "changed"), (2, "same"), (3, "added")]
    assert rows[0].original == "mov eax, ebx"
    assert rows[0].mutated == "mov eax, ecx"
    assert rows[2].original == ""
    assert rows[2].mutated == "nop"
    assert count_disasm_changed_lines(["mov eax, ebx", "ret"], ["mov eax, ecx", "ret", "nop"]) == 2
    assert count_byte_differences(b"\x90\x90", b"\x90\xcc\x90") == (2, 3)
