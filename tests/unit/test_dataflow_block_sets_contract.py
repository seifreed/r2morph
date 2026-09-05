from __future__ import annotations

from r2morph.analysis.dataflow_block_sets import compute_block_def, compute_block_use
from tests.utils.assertions import expect


def test_dataflow_block_sets_track_use_and_def() -> None:
    instructions = [
        {"disasm": "mov eax, ebx", "type": "mov"},
        {"disasm": "add ecx, eax", "type": "add"},
        {"disasm": "ret", "type": "ret"},
    ]

    expect(compute_block_def(instructions) == {("eax", 32), ("ecx", 32), ("rflags", 64)})
    expect(compute_block_use(instructions) == {("ebx", 32), ("memory", 0)})


def test_dataflow_block_sets_branch_reads_status_flags() -> None:
    instructions = [{"disasm": "jne 0x2000", "type": "cjmp"}]

    expect(compute_block_use(instructions) == {("rflags", 64)})


def test_dataflow_block_sets_arithmetic_defines_status_flags() -> None:
    instructions = [{"disasm": "add eax, ebx", "type": "add"}]

    expect(compute_block_def(instructions) == {("eax", 32), ("rflags", 64)})
