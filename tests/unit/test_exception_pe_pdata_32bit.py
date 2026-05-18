"""Regression: PE 32-bit (ARM) .pdata parsing must read 8-byte entries.

An ARM IMAGE_ARM_RUNTIME_FUNCTION_ENTRY is 8 bytes (BeginAddress + a
u32 of packed unwind data / .xdata RVA) -- there is no explicit End
field. The old code unpacked "<III" (12 bytes) on an 8-byte stride, so:

  * function_end was set to the unwind word (garbage: smaller than
    function_start), corrupting the ``start <= addr < end`` containment
    checks that consume these frames; and
  * the final entry's 12-byte slice ran past the buffer, raising
    struct.error and aborting the whole .pdata parse (losing entries).

No mocks (CLAUDE.md SS4): a real in-memory PE Binary double over a
synthetic .pdata buffer with packed-form entries.
"""

import struct

from tests._doubles.in_memory_pe_pdata_binary import InMemoryPEPdataBinary

from r2morph.analysis.exception import ExceptionInfoReader


def _packed_entry(begin: int, function_length_units: int) -> bytes:
    # Flag=0b01 (packed) | FunctionLength in bits [12:2], 2-byte units.
    second = 0x1 | ((function_length_units & 0x7FF) << 2)
    return struct.pack("<II", begin, second)


def test_pe_pdata_32bit_packed_entries_parsed_with_correct_extent() -> None:
    # Two 8-byte ARM entries (16 bytes total). Pre-fix: entry 0 gets a
    # bogus function_end and entry 1 is lost to a struct.error.
    pdata = _packed_entry(0x1000, 0x10) + _packed_entry(0x2000, 0x08)
    assert len(pdata) == 16

    binary = InMemoryPEPdataBinary(
        bits=32,
        pdata_addr=0x4000,
        pdata_declared_size=len(pdata),
        pdata_bytes=pdata,
    )
    frames = ExceptionInfoReader(binary).read_exception_frames()

    assert set(frames) == {0x1000, 0x2000}
    # FunctionLength is in 2-byte units: 0x10 -> 32 bytes, 0x08 -> 16.
    assert frames[0x1000].function_end == 0x1000 + 0x10 * 2
    assert frames[0x2000].function_end == 0x2000 + 0x08 * 2
    assert frames[0x1000].function_end > frames[0x1000].function_start


def test_pe_pdata_32bit_truncated_section_does_not_crash() -> None:
    # Declared size claims 3 entries (24 bytes) but only 2 entries worth
    # of bytes are actually readable. Must parse what fits, not raise.
    pdata = _packed_entry(0x1000, 0x10) + _packed_entry(0x2000, 0x08)

    binary = InMemoryPEPdataBinary(
        bits=32,
        pdata_addr=0x4000,
        pdata_declared_size=24,
        pdata_bytes=pdata,
    )
    frames = ExceptionInfoReader(binary).read_exception_frames()

    assert set(frames) == {0x1000, 0x2000}
