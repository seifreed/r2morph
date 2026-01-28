from pathlib import Path

import pytest

from r2morph.detection.entropy_analyzer import EntropyAnalyzer, EntropyResult


def test_entropy_analyzer_analyze_file_low_entropy(tmp_path: Path):
    sample = tmp_path / "zeros.bin"
    sample.write_bytes(b"\x00" * 2048)

    analyzer = EntropyAnalyzer()
    result = analyzer.analyze_file(sample)

    assert isinstance(result, EntropyResult)
    assert 0.0 <= result.overall_entropy <= 8.0
    assert result.is_packed is False
    assert isinstance(result.section_entropies, dict)
    assert isinstance(result.suspicious_sections, list)
    assert "Normal entropy" in result.analysis


def test_entropy_analyzer_compare_entropy_delta(tmp_path: Path):
    orig = tmp_path / "orig.bin"
    morph = tmp_path / "morph.bin"
    orig.write_bytes(b"\x00" * 1024)
    morph.write_bytes(bytes(range(256)) * 4)

    analyzer = EntropyAnalyzer()
    orig_entropy, morph_entropy, delta = analyzer.compare_entropy(orig, morph)

    assert 0.0 <= orig_entropy <= 8.0
    assert 0.0 <= morph_entropy <= 8.0
    assert abs(delta - (morph_entropy - orig_entropy)) < 1e-6


def test_entropy_analyzer_visualize_blocks(tmp_path: Path):
    sample = tmp_path / "blocks.bin"
    sample.write_bytes(bytes(range(256)) * 4)

    analyzer = EntropyAnalyzer()
    blocks = analyzer.visualize_entropy(sample, block_size=256)

    assert len(blocks) == 4
    assert all(0.0 <= value <= 8.0 for value in blocks)


def test_entropy_analyzer_sections_real():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    analyzer = EntropyAnalyzer()
    result = analyzer.analyze_file(binary_path)

    assert isinstance(result.section_entropies, dict)
    assert isinstance(result.suspicious_sections, list)
