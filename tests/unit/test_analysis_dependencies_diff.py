from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.analysis.dependencies import DependencyAnalyzer
from r2morph.analysis.diff_analyzer import DiffAnalyzer


def test_dependency_analyzer_basic() -> None:
    analyzer = DependencyAnalyzer()
    instructions = [
        {"offset": 0x1000, "disasm": "mov eax, ebx"},
        {"offset": 0x1002, "disasm": "add eax, 1"},
        {"offset": 0x1004, "disasm": "cmp eax, ecx"},
    ]
    deps = analyzer.analyze_dependencies(instructions)
    assert deps
    assert analyzer.has_dependency(0x1000, 0x1002) is True
    chain = analyzer.get_dependency_chain(0x1000)
    assert 0x1002 in chain
    dot = analyzer.to_dot()
    assert "Dependencies" in dot


def test_diff_analyzer_on_modified_copy(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    orig = tmp_path / "orig.bin"
    morph = tmp_path / "morph.bin"
    orig.write_bytes(source.read_bytes())
    data = bytearray(source.read_bytes())
    data[0] ^= 0xFF
    morph.write_bytes(data)

    diff = DiffAnalyzer()
    stats = diff.compare(orig, morph)
    assert stats.changed_bytes >= 1
    assert diff.get_similarity_score() < 100.0

    viz = diff.visualize_changes()
    assert "BINARY DIFF VISUALIZATION" in viz

    report_path = tmp_path / "report.md"
    diff.generate_report(report_path)
    assert report_path.exists()
