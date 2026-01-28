from pathlib import Path

import pytest

from r2morph.analysis.analyzer import BinaryAnalyzer
from r2morph.core.binary import Binary


def test_binary_analyzer_real_candidates_and_stats():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        analyzer = BinaryAnalyzer(bin_obj)

        functions = analyzer.get_functions_list()
        assert functions

        nop_candidates = analyzer.find_nop_insertion_candidates()
        subst_candidates = analyzer.find_substitution_candidates()

        assert isinstance(nop_candidates, list)
        assert isinstance(subst_candidates, list)

        stats = analyzer.get_statistics()
        assert stats["total_functions"] == len(functions)
        assert stats["total_instructions"] >= 0
        assert stats["total_basic_blocks"] >= 0

        hot = analyzer.identify_hot_functions()
        assert isinstance(hot, list)
