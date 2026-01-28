from pathlib import Path

import pytest

from r2morph.analysis.diff_analyzer import DiffAnalyzer


def test_diff_analyzer_identical_files(tmp_path: Path):
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    orig = tmp_path / "orig.bin"
    morph = tmp_path / "morph.bin"
    data = source.read_bytes()
    orig.write_bytes(data)
    morph.write_bytes(data)

    analyzer = DiffAnalyzer()
    stats = analyzer.compare(orig, morph)
    assert stats.changed_bytes == 0
    assert analyzer.get_similarity_score() == 100.0


def test_diff_analyzer_visualization_writes_file(tmp_path: Path):
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    orig = tmp_path / "orig.bin"
    morph = tmp_path / "morph.bin"
    orig.write_bytes(source.read_bytes())

    mutated = bytearray(source.read_bytes())
    if mutated:
        mutated[-1] ^= 0xFF
    morph.write_bytes(bytes(mutated))

    analyzer = DiffAnalyzer()
    analyzer.compare(orig, morph)

    output_file = tmp_path / "viz.txt"
    viz = analyzer.visualize_changes(output_file)
    assert output_file.exists()
    assert "BINARY DIFF VISUALIZATION" in viz


def test_diff_analyzer_report_contains_sections(tmp_path: Path):
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    orig = tmp_path / "orig.bin"
    morph = tmp_path / "morph.bin"
    orig.write_bytes(source.read_bytes())

    mutated = bytearray(source.read_bytes())
    if mutated:
        mutated[0] ^= 0xAA
    morph.write_bytes(bytes(mutated))

    analyzer = DiffAnalyzer()
    analyzer.compare(orig, morph)

    report = tmp_path / "report.md"
    analyzer.generate_report(report)
    content = report.read_text()
    assert "# Binary Diff Analysis Report" in content
    assert "## Summary" in content
    assert "## Metrics" in content
