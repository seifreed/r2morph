from pathlib import Path
import shutil

import pytest

from r2morph.analysis.diff_analyzer import DiffAnalyzer


def _flip_first_byte(path: Path) -> None:
    data = path.read_bytes()
    if not data:
        return
    flipped = bytes([data[0] ^ 0xFF]) + data[1:]
    path.write_bytes(flipped)


def test_diff_analyzer_real_compare_and_report(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    original = tmp_path / "orig_bin"
    morphed = tmp_path / "morphed_bin"
    shutil.copy(binary_path, original)
    shutil.copy(binary_path, morphed)
    _flip_first_byte(morphed)

    analyzer = DiffAnalyzer()
    stats = analyzer.compare(original, morphed)
    assert stats.total_bytes > 0
    assert stats.changed_bytes >= 1

    similarity = analyzer.get_similarity_score()
    assert 0.0 <= similarity <= 100.0

    viz_path = tmp_path / "diff_viz.txt"
    viz = analyzer.visualize_changes(viz_path)
    assert "BINARY DIFF VISUALIZATION" in viz
    assert viz_path.exists()

    report_path = tmp_path / "diff_report.md"
    analyzer.generate_report(report_path)
    assert report_path.exists()
    assert "Binary Diff Analysis Report" in report_path.read_text()
