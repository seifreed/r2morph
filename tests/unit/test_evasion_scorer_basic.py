from pathlib import Path

import pytest

from r2morph.detection.evasion_scorer import EvasionScore, EvasionScorer
from tests.utils.assertions import expect

_EXPECTED_0_0_100_0 = 100.0
_EXPECTED_0_0_100_0_2 = 100.0
_EXPECTED_SCORER_SCORE_HASH_CHANGE_ORIGINAL_MORPHED_100_0 = 100.0
_EXPECTED_SIGNATURE_SCORE_100_0 = 100.0


def test_evasion_score_string_formatting():
    score = EvasionScore(
        overall_score=75.0,
        hash_change_score=100.0,
        entropy_score=80.0,
        structure_score=60.0,
        signature_score=50.0,
        details={"hash_changed": True},
    )
    text = str(score)
    expect(not ("Evasion Score" not in text))
    expect(not ("Hash Change" not in text))
    expect(not ("Entropy" not in text))
    expect(not ("Structure" not in text))
    expect(not ("Signature" not in text))


def test_evasion_scorer_hash_entropy_signature_scores(tmp_path: Path):
    scorer = EvasionScorer()

    original = tmp_path / "orig.bin"
    morphed = tmp_path / "morph.bin"

    original.write_bytes(b"\x00" * 128)
    morphed.write_bytes(b"\x01" * 128)

    expect(scorer._score_hash_change(original, morphed) == _EXPECTED_SCORER_SCORE_HASH_CHANGE_ORIGINAL_MORPHED_100_0)

    entropy_score = scorer._score_entropy(original, morphed)
    expect(0.0 <= entropy_score <= _EXPECTED_0_0_100_0)

    signature_score = scorer._score_signatures(original, morphed)
    expect(not (signature_score < 0.0))
    expect(not (signature_score > _EXPECTED_SIGNATURE_SCORE_100_0))


def test_evasion_scorer_structure_score_with_real_binary(tmp_path: Path):
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    original = tmp_path / "orig_elf"
    morphed = tmp_path / "morph_elf"
    original.write_bytes(binary_path.read_bytes())
    morphed.write_bytes(binary_path.read_bytes())

    scorer = EvasionScorer()
    structure_score = scorer._score_structure(original, morphed)
    expect(0.0 <= structure_score <= _EXPECTED_0_0_100_0_2)


def test_evasion_scorer_recommendations_thresholds():
    scorer = EvasionScorer()
    score = EvasionScore(
        overall_score=30.0,
        hash_change_score=0.0,
        entropy_score=20.0,
        structure_score=10.0,
        signature_score=10.0,
        details={},
    )
    recommendations = scorer.recommend_improvements(score)
    expect(any("Low evasion score" in rec or "Low evasion" in rec for rec in recommendations))
