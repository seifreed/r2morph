"""Regression: CodeMobilityPass must skip blocks whose cave is farther
than an x86 e9 rel32 can reach, not crash with OverflowError.

Pre-fix, ret_offset/tramp_offset were fed straight into
int.to_bytes(4, "little", signed=True) with no range check, so a cave
> 2 GiB from the block raised OverflowError and aborted the *entire*
pass (every later block lost). The codebase already guards this exact
way in import_obfuscation/full_cff; this applies the same guard.
Real in-memory double, no mocks.
"""

from __future__ import annotations

from r2morph.mutations.code_mobility import CodeMobilityPass
from tests._doubles.in_memory_mobility_binary import InMemoryMobilityBinary

CONFIG = {"probability": 1.0, "preserve_order": True}
FUNCS = [{"addr": 0x1000, "size": 64}]
BLOCKS = [{"addr": 0x1000, "size": 32, "type": "function", "jump": None, "fail": None}]
DISASM = [{"disasm": "mov eax, ebx"}]


def test_far_cave_offset_is_skipped_not_overflowerror() -> None:
    # Cave at 0x90000000 (~2.4 GiB) is unreachable by e9 rel32 from 0x1000.
    binary = InMemoryMobilityBinary(
        regions={0x1000: b"\xcc" * 64, 0x90000000: b"\x90" * 128},
        functions=FUNCS,
        blocks=BLOCKS,
        disasm=DISASM,
        sections=[{"name": ".farx", "vaddr": 0x90000000, "vsize": 128, "perm": "r-x"}],
    )
    p = CodeMobilityPass(CONFIG)

    result = p.apply(binary)  # pre-fix: raises OverflowError

    assert result["blocks_moved"] == 0
    assert p.get_records() == []


def test_in_range_cave_still_moves_block() -> None:
    # Near cave at 0x2000 is reachable; behavior must be unchanged.
    binary = InMemoryMobilityBinary(
        regions={0x1000: b"\xcc" * 64, 0x2000: b"\x90" * 128},
        functions=FUNCS,
        blocks=BLOCKS,
        disasm=DISASM,
        sections=[{"name": ".x", "vaddr": 0x2000, "vsize": 128, "perm": "r-x"}],
    )
    p = CodeMobilityPass(CONFIG)

    result = p.apply(binary)

    assert result["blocks_moved"] == 1
    assert len(p.get_records()) == 1
