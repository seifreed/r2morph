from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.detection.evasion_scorer import EvasionScorer, EvasionScore


def test_evasion_scorer_on_real_files(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    original = tmp_path / "orig.bin"
    mutated = tmp_path / "mut.bin"
    shutil.copyfile(source, original)
    shutil.copyfile(source, mutated)

    data = mutated.read_bytes()
    if data:
        mutated.write_bytes(bytes([data[0] ^ 0xFF]) + data[1:])

    scorer = EvasionScorer()
    score = scorer.score(original, mutated)

    assert isinstance(score, EvasionScore)
    assert 0.0 <= score.overall_score <= 100.0

    recommendations = scorer.recommend_improvements(score)
    assert recommendations


def test_evasion_scorer_recommendations_edges() -> None:
    scorer = EvasionScorer()
    high = EvasionScore(
        overall_score=90.0,
        hash_change_score=100.0,
        entropy_score=90.0,
        structure_score=80.0,
        signature_score=80.0,
        details={},
    )
    low = EvasionScore(
        overall_score=10.0,
        hash_change_score=0.0,
        entropy_score=10.0,
        structure_score=0.0,
        signature_score=10.0,
        details={},
    )

    assert any("Excellent" in msg or "✅" in msg for msg in scorer.recommend_improvements(high))
    assert any("Low evasion" in msg or "🔴" in msg for msg in scorer.recommend_improvements(low))
