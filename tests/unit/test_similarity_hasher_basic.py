from pathlib import Path

from r2morph.detection.similarity_hasher import SimilarityHasher
from tests.utils.assertions import expect

_EXPECTED_HASHER_BYTE_SIMILARITY_FILE_A_FILE_B_100_0 = 100.0


def test_similarity_hasher_check_tool_missing():
    hasher = SimilarityHasher()
    expect(not (hasher._check_tool("definitely-not-a-real-tool") is not False))


def test_similarity_hasher_byte_similarity(tmp_path: Path):
    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    file_c = tmp_path / "c.bin"

    file_a.write_bytes(b"\x00" * 16)
    file_b.write_bytes(b"\x00" * 16)
    file_c.write_bytes(b"\x01" * 8)

    hasher = SimilarityHasher()
    expect(hasher._byte_similarity(file_a, file_b) == _EXPECTED_HASHER_BYTE_SIMILARITY_FILE_A_FILE_B_100_0)
    expect(hasher._byte_similarity(file_a, file_c) == 0.0)
