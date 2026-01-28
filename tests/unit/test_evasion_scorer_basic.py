from pathlib import Path

import pytest

from r2morph.detection.evasion_scorer import EvasionScorer, EvasionScore


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
    assert "Evasion Score" in text
    assert "Hash Change" in text
    assert "Entropy" in text
    assert "Structure" in text
    assert "Signature" in text


def test_evasion_scorer_hash_entropy_signature_scores(tmp_path: Path):
    scorer = EvasionScorer()

    original = tmp_path / "orig.bin"
    morphed = tmp_path / "morph.bin"

    original.write_bytes(b"\x00" * 128)
    morphed.write_bytes(b"\x01" * 128)

    assert scorer._score_hash_change(original, morphed) == 100.0

    entropy_score = scorer._score_entropy(original, morphed)
    assert 0.0 <= entropy_score <= 100.0

    signature_score = scorer._score_signatures(original, morphed)
    assert signature_score >= 0.0
    assert signature_score <= 100.0


def test_evasion_scorer_structure_score_with_real_binary(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    original = tmp_path / "orig_elf"
    morphed = tmp_path / "morph_elf"
    original.write_bytes(binary_path.read_bytes())
    morphed.write_bytes(binary_path.read_bytes())

    scorer = EvasionScorer()
    structure_score = scorer._score_structure(original, morphed)
    assert 0.0 <= structure_score <= 100.0


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
    assert any("Low evasion score" in rec or "Low evasion" in rec for rec in recommendations)
