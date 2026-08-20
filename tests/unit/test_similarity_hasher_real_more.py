from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.detection.similarity_hasher import SimilarityHasher
from tests.utils.assertions import expect

_EXPECTED_0_0_100_0 = 100.0
_EXPECTED_RESULT_SAME_BYTE_SIMILARITY_100_0 = 100.0


def test_similarity_hasher_byte_comparison(tmp_path: Path) -> None:
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    file_a.write_bytes(source.read_bytes())
    file_b.write_bytes(source.read_bytes())

    hasher = SimilarityHasher()
    result_same = hasher.compare_files(file_a, file_b)
    expect(result_same["byte_similarity"] == _EXPECTED_RESULT_SAME_BYTE_SIMILARITY_100_0)

    data = bytearray(file_b.read_bytes())
    data[0] ^= 0xFF
    file_b.write_bytes(data)

    result_diff = hasher.compare_files(file_a, file_b)
    expect(0.0 <= result_diff["byte_similarity"] < _EXPECTED_0_0_100_0)
