from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.analysis.dependencies import DependencyAnalyzer
from r2morph.analysis.diff_analyzer import DiffAnalyzer
from tests.utils.assertions import expect

_EXPECTED_CHAIN_4098 = 0x1002
_EXPECTED_DIFF_GET_SIMILARITY_SCORE_100_0 = 100.0


def test_dependency_analyzer_basic() -> None:
    analyzer = DependencyAnalyzer()
    instructions = [
        {"offset": 0x1000, "disasm": "mov eax, ebx"},
        {"offset": 0x1002, "disasm": "add eax, 1"},
        {"offset": 0x1004, "disasm": "cmp eax, ecx"},
    ]
    deps = analyzer.analyze_dependencies(instructions)
    expect(deps)
    expect(not (analyzer.has_dependency(0x1000, 0x1002) is not True))
    chain = analyzer.get_dependency_chain(0x1000)
    expect(not (_EXPECTED_CHAIN_4098 not in chain))
    dot = analyzer.to_dot()
    expect(not ("Dependencies" not in dot))


def test_diff_analyzer_on_modified_copy(tmp_path: Path) -> None:
    source = Path("fixtures/dataset/elf_x86_64")
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
    expect(not (stats.changed_bytes < 1))
    expect(not (diff.get_similarity_score() >= _EXPECTED_DIFF_GET_SIMILARITY_SCORE_100_0))

    viz = diff.visualize_changes()
    expect(not ("BINARY DIFF VISUALIZATION" not in viz))

    report_path = tmp_path / "report.md"
    diff.generate_report(report_path)
    expect(report_path.exists())
