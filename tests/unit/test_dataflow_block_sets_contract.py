from __future__ import annotations

from r2morph.analysis.dataflow_block_sets import compute_block_def, compute_block_use


def test_dataflow_block_sets_track_use_and_def() -> None:
    instructions = [
        {"disasm": "mov eax, ebx", "type": "mov"},
        {"disasm": "add ecx, eax", "type": "add"},
        {"disasm": "ret", "type": "ret"},
    ]

    assert compute_block_def(instructions) == {("eax", 32), ("ecx", 32)}
    assert compute_block_use(instructions) == {("ebx", 32)}
