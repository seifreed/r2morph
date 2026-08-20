from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.analysis.analyzer import BinaryAnalyzer
from r2morph.analysis.cfg import CFGBuilder
from r2morph.core.binary import Binary
from tests.utils.assertions import expect


def test_binary_analyzer_candidates_and_stats() -> None:
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    with Binary(source) as binary:
        binary.analyze()
        analyzer = BinaryAnalyzer(binary)

        functions = analyzer.get_functions_list()
        expect(functions)

        stats = analyzer.get_statistics()
        expect(not (stats["total_functions"] < 1))
        expect(not (stats["total_instructions"] < 0))

        nop_candidates = analyzer.find_nop_insertion_candidates()
        sub_candidates = analyzer.find_substitution_candidates()
        expect(isinstance(nop_candidates, list))
        expect(isinstance(sub_candidates, list))

        hot = analyzer.identify_hot_functions()
        expect(isinstance(hot, list))


def test_cfg_builder_real_function() -> None:
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    with Binary(source) as binary:
        binary.analyze()
        funcs = binary.get_functions()
        if not funcs:
            pytest.skip("No functions found")

        func = funcs[0]
        addr = func.get("offset", 0) or func.get("addr", 0)
        expect(addr)

        builder = CFGBuilder(binary)
        cfg = builder.build_cfg(addr, func.get("name", "func"))

        expect(cfg.blocks)
        expect(not (cfg.get_complexity() < 1))
        expect(cfg.entry_block is not None)
        expect(isinstance(cfg.to_dot(), str))

        dominators = cfg.compute_dominators()
        expect(not (cfg.entry_block.address not in dominators))
