"""Contract tests for binary diff helpers."""

from __future__ import annotations

from r2morph.validation.differ_helpers import compare_section_bytes, compute_byte_diffs


class _FakeBinary:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read_bytes(self, _addr: int, size: int) -> bytes:
        return self._data[:size]


def test_compute_byte_diffs_tracks_context_and_tail() -> None:
    diffs = compute_byte_diffs(b"ABCD", b"ABXDZ", 0x1000, 1)

    assert len(diffs) == 2
    assert diffs[0].offset == 0x1002
    assert diffs[0].context_before == b"B"
    assert diffs[0].context_after == b"D"
    assert diffs[1].offset == 0x1004
    assert diffs[1].original == b""
    assert diffs[1].mutated == b"Z"


def test_compare_section_bytes_uses_binary_readers() -> None:
    original = _FakeBinary(b"ABCD")
    mutated = _FakeBinary(b"ABXD")

    diffs = compare_section_bytes(
        original,
        mutated,
        {"addr": 0x1000, "size": 4},
        {"addr": 0x1000, "size": 4},
        1,
    )

    assert len(diffs) == 1
    assert diffs[0].offset == 0x1002
