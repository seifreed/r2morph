from pathlib import Path

import pytest

from r2morph.analysis.diff_analyzer import DiffAnalyzer
from tests.utils.assertions import expect

_EXPECTED_ANALYZER_GET_SIMILARITY_SCORE_100_0 = 100.0


def test_diff_analyzer_identical_files(tmp_path: Path):
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    orig = tmp_path / "orig.bin"
    morph = tmp_path / "morph.bin"
    data = source.read_bytes()
    orig.write_bytes(data)
    morph.write_bytes(data)

    analyzer = DiffAnalyzer()
    stats = analyzer.compare(orig, morph)
    expect(stats.changed_bytes == 0)
    expect(analyzer.get_similarity_score() == _EXPECTED_ANALYZER_GET_SIMILARITY_SCORE_100_0)


def test_diff_analyzer_visualization_writes_file(tmp_path: Path):
    source = Path("fixtures/dataset/elf_x86_64")
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
    expect(output_file.exists())
    expect(not ("BINARY DIFF VISUALIZATION" not in viz))


def test_diff_analyzer_report_contains_sections(tmp_path: Path):
    source = Path("fixtures/dataset/elf_x86_64")
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
    expect(not ("# Binary Diff Analysis Report" not in content))
    expect(not ("## Summary" not in content))
    expect(not ("## Metrics" not in content))
