"""Regression: APIHashingPass must skip out-of-int32 e9/e8 rel32
offsets instead of crashing with OverflowError.

Same class as the iter-8/9 code_mobility/function_outlining fixes.
jmp_off (cave -> PLT, e9) and new_off (call site -> cave, e8) were fed
straight into int.to_bytes(4, "little", signed=True) with no range
check; a cave > 2 GiB from the PLT or a call site raised OverflowError
and aborted the whole pass. The codebase already guards this in
import_obfuscation/full_cff. Real sparse in-memory double, no mocks.
"""

from __future__ import annotations

from r2morph.mutations.api_hashing import APIHashingPass
from tests._doubles.in_memory_api_hashing_sparse_binary import InMemoryAPIHashingSparseBinary

CONFIG = {"api_list": ["MyApi"]}


def test_far_cave_stub_jump_is_skipped_not_overflowerror() -> None:
    # PLT at 0x2000, cave section ~2.4 GiB away -> jmp_off overflows int32.
    binary = InMemoryAPIHashingSparseBinary(
        regions={0x90000000: b"\x90" * 64},
        section={"name": ".farx", "vaddr": 0x90000000, "vsize": 64, "perm": "r-x"},
        imports=[{"name": "MyApi", "plt": 0x2000}],
        xrefs=[],
    )
    p = APIHashingPass(CONFIG)

    result = p.apply(binary)  # pre-fix: raises OverflowError at jmp_off

    assert result["imports_hashed"] == 0
    assert p.get_records() == []


def test_far_call_site_offset_is_skipped_not_overflowerror() -> None:
    # PLT and cave both high & near (jmp_off in range); call site low so
    # new_off (cave - call_site) overflows int32.
    binary = InMemoryAPIHashingSparseBinary(
        regions={
            0x1000: b"\xe8\x00\x00\x00\x00" + b"\xcc" * 11,
            0x90001000: b"\x90" * 64,
        },
        section={"name": ".farx", "vaddr": 0x90001000, "vsize": 64, "perm": "r-x"},
        imports=[{"name": "MyApi", "plt": 0x90000000}],
        xrefs=[{"from": 0x1000}],
    )
    p = APIHashingPass(CONFIG)

    result = p.apply(binary)  # pre-fix: raises OverflowError at new_off

    assert result["imports_hashed"] == 0
    assert p.get_records() == []


def test_in_range_offsets_still_hash_import() -> None:
    # Everything reachable by e9/e8 rel32 -> behavior unchanged.
    buf = bytearray(128)
    buf[0:5] = b"\xe8\x00\x00\x00\x00"
    buf[5:0x40] = b"\xcc" * (0x40 - 5)
    buf[0x40:0x80] = b"\x90" * 0x40
    binary = InMemoryAPIHashingSparseBinary(
        regions={0x1000: bytes(buf)},
        section={"name": ".text", "vaddr": 0x1000, "vsize": 128, "perm": "r-x"},
        imports=[{"name": "MyApi", "plt": 0x2000}],
        xrefs=[{"from": 0x1000}],
    )
    p = APIHashingPass(CONFIG)

    result = p.apply(binary)

    assert result["imports_hashed"] == 1
    assert len(p.get_records()) == 1
