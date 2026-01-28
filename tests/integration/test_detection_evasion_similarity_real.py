from pathlib import Path

import pytest

from r2morph.detection.evasion_scorer import EvasionScorer
from r2morph.detection.similarity_hasher import SimilarityHasher


def _copy_binary(tmp_path: Path, name: str) -> Path:
    src = Path("dataset/elf_x86_64")
    dst = tmp_path / name
    dst.write_bytes(src.read_bytes())
    return dst


def test_evasion_scorer_real(tmp_path: Path):
    original = Path("dataset/elf_x86_64")
    if not original.exists():
        pytest.skip("ELF binary not available")

    morphed = _copy_binary(tmp_path, "elf_morphed")
    data = bytearray(morphed.read_bytes())
    data[0] ^= 0xFF
    morphed.write_bytes(data)

    scorer = EvasionScorer()
    score = scorer.score(original, morphed)

    assert 0.0 <= score.overall_score <= 100.0
    assert 0.0 <= score.hash_change_score <= 100.0
    assert 0.0 <= score.entropy_score <= 100.0
    assert 0.0 <= score.structure_score <= 100.0
    assert 0.0 <= score.signature_score <= 100.0
    assert "hash_changed" in score.details


def test_similarity_hasher_real(tmp_path: Path):
    original = Path("dataset/elf_x86_64")
    if not original.exists():
        pytest.skip("ELF binary not available")

    same_copy = _copy_binary(tmp_path, "elf_copy")
    modified = _copy_binary(tmp_path, "elf_modified")
    modified_data = bytearray(modified.read_bytes())
    modified_data[-1] ^= 0xAA
    modified.write_bytes(modified_data)

    hasher = SimilarityHasher()
    hashes = hasher.hash_file(original)
    assert "ssdeep" in hashes
    assert "tlsh" in hashes

    same_result = hasher.compare_files(original, same_copy)
    assert same_result["byte_similarity"] == 100.0

    diff_result = hasher.compare_files(original, modified)
    assert diff_result["byte_similarity"] < 100.0
