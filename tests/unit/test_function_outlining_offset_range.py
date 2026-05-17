"""Regression: FunctionOutliningPass must skip chunks whose cave is
farther than an x86 e9 rel32 can reach, not crash with OverflowError.

Same class as the iter-8 code_mobility fix: ret_off/tramp_off were fed
straight into int.to_bytes(4, "little", signed=True) with no range
check, so a cave > 2 GiB from the chunk raised OverflowError and
aborted the entire pass. The codebase already guards this in
import_obfuscation/full_cff; this applies the same guard. Real
in-memory double, no mocks.
"""

from __future__ import annotations

from r2morph.mutations.function_outlining import FunctionOutliningPass
from tests._doubles.in_memory_outlining_binary import InMemoryOutliningBinary

CONFIG = {"probability": 1.0, "min_chunks": 2, "max_chunks": 2}
FUNCS = [{"addr": 0x1000, "size": 64}]
BLOCKS = [{"addr": 0x1000, "size": 8}, {"addr": 0x1008, "size": 8}]
PDJ = {
    0x1000: [
        {"offset": 0x1000, "size": 4, "disasm": "mov eax, ebx"},
        {"offset": 0x1004, "size": 4, "disasm": "nop"},
    ],
    0x1008: [
        {"offset": 0x1008, "size": 4, "disasm": "mov ecx, edx"},
        {"offset": 0x100C, "size": 4, "disasm": "nop"},
    ],
}


def test_far_cave_offset_is_skipped_not_overflowerror() -> None:
    binary = InMemoryOutliningBinary(
        regions={0x1000: b"\xcc" * 16, 0x90000000: b"\x90" * 128},
        functions=FUNCS,
        blocks=BLOCKS,
        pdj=PDJ,
        sections=[{"name": ".farx", "vaddr": 0x90000000, "vsize": 128, "perm": "r-x"}],
    )
    p = FunctionOutliningPass(CONFIG)

    result = p.apply(binary)  # pre-fix: raises OverflowError

    assert result["chunks_relocated"] == 0
    assert p.get_records() == []


def test_in_range_cave_still_outlines_chunk() -> None:
    binary = InMemoryOutliningBinary(
        regions={0x1000: b"\xcc" * 16, 0x2000: b"\x90" * 128},
        functions=FUNCS,
        blocks=BLOCKS,
        pdj=PDJ,
        sections=[{"name": ".x", "vaddr": 0x2000, "vsize": 128, "perm": "r-x"}],
    )
    p = FunctionOutliningPass(CONFIG)

    result = p.apply(binary)

    assert result["chunks_relocated"] == 1
    assert len(p.get_records()) == 1
