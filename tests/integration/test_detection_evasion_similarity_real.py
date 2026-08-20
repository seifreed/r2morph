from pathlib import Path

import pytest

from r2morph.detection.evasion_scorer import EvasionScorer
from r2morph.detection.similarity_hasher import SimilarityHasher
from tests.utils.assertions import expect

_EXPECTED_0_0_100_0 = 100.0
_EXPECTED_0_0_100_0_2 = 100.0
_EXPECTED_0_0_100_0_3 = 100.0
_EXPECTED_0_0_100_0_4 = 100.0
_EXPECTED_0_0_100_0_5 = 100.0
_EXPECTED_DIFF_RESULT_BYTE_SIMILARITY_100_0 = 100.0
_EXPECTED_SAME_RESULT_BYTE_SIMILARITY_100_0 = 100.0


def _copy_binary(tmp_path: Path, name: str) -> Path:
    src = Path("fixtures/dataset/elf_x86_64")
    dst = tmp_path / name
    dst.write_bytes(src.read_bytes())
    return dst


def test_evasion_scorer_real(tmp_path: Path):
    original = Path("fixtures/dataset/elf_x86_64")
    if not original.exists():
        pytest.skip("ELF binary not available")

    morphed = _copy_binary(tmp_path, "elf_morphed")
    data = bytearray(morphed.read_bytes())
    data[0] ^= 0xFF
    morphed.write_bytes(data)

    scorer = EvasionScorer()
    score = scorer.score(original, morphed)

    expect(0.0 <= score.overall_score <= _EXPECTED_0_0_100_0)
    expect(0.0 <= score.hash_change_score <= _EXPECTED_0_0_100_0_2)
    expect(0.0 <= score.entropy_score <= _EXPECTED_0_0_100_0_3)
    expect(0.0 <= score.structure_score <= _EXPECTED_0_0_100_0_4)
    expect(0.0 <= score.signature_score <= _EXPECTED_0_0_100_0_5)
    expect(not ("hash_changed" not in score.details))


def test_similarity_hasher_real(tmp_path: Path):
    original = Path("fixtures/dataset/elf_x86_64")
    if not original.exists():
        pytest.skip("ELF binary not available")

    same_copy = _copy_binary(tmp_path, "elf_copy")
    modified = _copy_binary(tmp_path, "elf_modified")
    modified_data = bytearray(modified.read_bytes())
    modified_data[-1] ^= 0xAA
    modified.write_bytes(modified_data)

    hasher = SimilarityHasher()
    hashes = hasher.hash_file(original)
    expect(not ("ssdeep" not in hashes))
    expect(not ("tlsh" not in hashes))

    same_result = hasher.compare_files(original, same_copy)
    expect(same_result["byte_similarity"] == _EXPECTED_SAME_RESULT_BYTE_SIMILARITY_100_0)

    diff_result = hasher.compare_files(original, modified)
    expect(not (diff_result["byte_similarity"] >= _EXPECTED_DIFF_RESULT_BYTE_SIMILARITY_100_0))
