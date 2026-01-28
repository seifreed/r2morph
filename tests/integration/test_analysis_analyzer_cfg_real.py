from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.analysis.analyzer import BinaryAnalyzer
from r2morph.analysis.cfg import CFGBuilder
from r2morph.core.binary import Binary


def test_binary_analyzer_candidates_and_stats() -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    with Binary(source) as binary:
        binary.analyze()
        analyzer = BinaryAnalyzer(binary)

        functions = analyzer.get_functions_list()
        assert functions

        stats = analyzer.get_statistics()
        assert stats["total_functions"] >= 1
        assert stats["total_instructions"] >= 0

        nop_candidates = analyzer.find_nop_insertion_candidates()
        sub_candidates = analyzer.find_substitution_candidates()
        assert isinstance(nop_candidates, list)
        assert isinstance(sub_candidates, list)

        hot = analyzer.identify_hot_functions()
        assert isinstance(hot, list)


def test_cfg_builder_real_function() -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    with Binary(source) as binary:
        binary.analyze()
        funcs = binary.get_functions()
        if not funcs:
            pytest.skip("No functions found")

        func = funcs[0]
        addr = func.get("offset", 0) or func.get("addr", 0)
        assert addr

        builder = CFGBuilder(binary)
        cfg = builder.build_cfg(addr, func.get("name", "func"))

        assert cfg.blocks
        assert cfg.get_complexity() >= 1
        assert cfg.entry_block is not None
        assert isinstance(cfg.to_dot(), str)

        dominators = cfg.compute_dominators()
        assert cfg.entry_block.address in dominators
