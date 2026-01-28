from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.evasion_scorer import EvasionScorer, EvasionScore
from r2morph.detection.obfuscation_detector import ObfuscationDetector
from r2morph.detection.similarity_hasher import SimilarityHasher


def test_evasion_scorer_hash_entropy_and_recommendations(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    orig = tmp_path / "orig.bin"
    morph = tmp_path / "morph.bin"
    orig.write_bytes(source.read_bytes())
    data = bytearray(source.read_bytes())
    data[0] = (data[0] + 1) % 256
    morph.write_bytes(bytes(data))

    scorer = EvasionScorer()
    score = scorer.score(orig, morph)
    assert 0.0 <= score.overall_score <= 100.0
    assert score.hash_change_score == 100.0

    low_score = EvasionScore(
        overall_score=0.0,
        hash_change_score=0.0,
        entropy_score=0.0,
        structure_score=0.0,
        signature_score=0.0,
        details={},
    )
    recs = scorer.recommend_improvements(low_score)
    assert any("Hash didn't change" in item for item in recs)


def test_similarity_hasher_byte_similarity_without_tools(tmp_path: Path) -> None:
    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    file_a.write_bytes(b"ABCDE")
    file_b.write_bytes(b"ABCDF")

    hasher = SimilarityHasher()
    hasher.has_ssdeep = False
    hasher.has_tlsh = False

    hashes = hasher.hash_file(file_a)
    assert hashes["ssdeep"] is None
    assert hashes["tlsh"] is None

    result = hasher.compare_files(file_a, file_b)
    assert result["byte_similarity"] < 100.0


def test_obfuscation_detector_report_real_binary(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "obfus.bin"
    work_path.write_bytes(source.read_bytes() + b"IsDebuggerPresent\\x00vmware\\x00")

    detector = ObfuscationDetector()
    with Binary(work_path) as binary:
        binary.analyze()
        report = detector.get_comprehensive_report(binary)

    assert "timestamp" in report
    assert "obfuscation_analysis" in report
    assert isinstance(report.get("recommendations", []), list)
