from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.detection.similarity_hasher import SimilarityHasher
from tests.utils.assertions import expect

_EXPECTED_DIFF_BYTE_SIMILARITY_100_0 = 100.0
_EXPECTED_SAME_BYTE_SIMILARITY_100_0 = 100.0


def test_similarity_hasher_byte_similarity(tmp_path: Path) -> None:
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    original = tmp_path / "original.bin"
    modified = tmp_path / "modified.bin"
    shutil.copyfile(source, original)
    shutil.copyfile(source, modified)

    data = modified.read_bytes()
    if not data:
        pytest.skip("Empty test binary")
    modified.write_bytes(bytes([data[0] ^ 0xFF]) + data[1:])

    hasher = SimilarityHasher()
    same = hasher.compare_files(original, original)
    diff = hasher.compare_files(original, modified)

    expect(same["byte_similarity"] == _EXPECTED_SAME_BYTE_SIMILARITY_100_0)
    expect(not (diff["byte_similarity"] >= _EXPECTED_DIFF_BYTE_SIMILARITY_100_0))


def test_similarity_hasher_hashes(tmp_path: Path) -> None:
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    copy_path = tmp_path / "hash.bin"
    shutil.copyfile(source, copy_path)

    hasher = SimilarityHasher()
    hashes = hasher.hash_file(copy_path)

    expect(set(hashes.keys()) == {"ssdeep", "tlsh"})
    expect(hashes["ssdeep"] is None or isinstance(hashes["ssdeep"], str))
    expect(hashes["tlsh"] is None or isinstance(hashes["tlsh"], str))
