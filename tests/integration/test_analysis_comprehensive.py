"""
Comprehensive real tests for all analysis modules.
"""

import importlib.util
from pathlib import Path

import pytest

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


from r2morph import MorphEngine
from r2morph.analysis.analyzer import BinaryAnalyzer
from r2morph.analysis.cfg import BasicBlock, CFGBuilder, ControlFlowGraph
from r2morph.analysis.dependencies import DependencyAnalyzer
from r2morph.analysis.diff_analyzer import DiffAnalyzer
from r2morph.analysis.invariants import InvariantDetector
from r2morph.core.binary import Binary
from r2morph.mutations import NopInsertionPass


class TestBinaryAnalyzerComprehensive:
    """Comprehensive tests for BinaryAnalyzer."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_get_functions_list(self, ls_elf):
        """Test getting function list."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            analyzer = BinaryAnalyzer(binary)
            functions = analyzer.get_functions_list()

            assert isinstance(functions, list)
            assert len(functions) > 0

    def test_get_instructions_for_function(self, ls_elf):
        """Test getting instructions for function."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            analyzer = BinaryAnalyzer(binary)
            functions = binary.get_functions()

            if len(functions) > 0:
                addr = functions[0].get("offset", 0)
                if addr:
                    instructions = analyzer.get_instructions_for_function(addr)
                    assert isinstance(instructions, list)

    def test_find_nop_insertion_candidates(self, ls_elf):
        """Test finding NOP insertion candidates."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            analyzer = BinaryAnalyzer(binary)
            candidates = analyzer.find_nop_insertion_candidates()

            assert isinstance(candidates, list)

    def test_find_substitution_candidates(self, ls_elf):
        """Test finding substitution candidates."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            analyzer = BinaryAnalyzer(binary)
            candidates = analyzer.find_substitution_candidates()

            assert isinstance(candidates, list)

    def test_get_statistics(self, ls_elf):
        """Test getting statistics."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            analyzer = BinaryAnalyzer(binary)
            stats = analyzer.get_statistics()

            assert isinstance(stats, dict)
            assert "architecture" in stats
            assert "total_functions" in stats
            assert "total_instructions" in stats

    def test_identify_hot_functions(self, ls_elf):
        """Test identifying hot functions."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            analyzer = BinaryAnalyzer(binary)
            hot_funcs = analyzer.identify_hot_functions(min_size=50)

            assert isinstance(hot_funcs, list)


class TestCFGBuilder:
    """Comprehensive tests for CFGBuilder."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_build_cfg(self, ls_elf):
        """Test building CFG."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            functions = binary.get_functions()

            if len(functions) > 0:
                func = functions[0]
                addr = func.get("offset", func.get("addr", 0))
                name = func.get("name", "unknown")

                builder = CFGBuilder(binary)
                cfg = builder.build_cfg(addr, name)

                assert isinstance(cfg, ControlFlowGraph)
                assert cfg.function_address == addr
                assert len(cfg.blocks) > 0

    def test_basic_block_operations(self):
        """Test BasicBlock operations."""
        block = BasicBlock(address=0x1000, size=16)

        block.add_successor(0x1010)
        assert 0x1010 in block.successors

        block.add_predecessor(0x0FF0)
        assert 0x0FF0 in block.predecessors

        assert "0x1000" in repr(block)

    def test_cfg_operations(self):
        """Test ControlFlowGraph operations."""
        cfg = ControlFlowGraph(function_address=0x1000, function_name="test")

        block1 = BasicBlock(address=0x1000, size=16)
        block2 = BasicBlock(address=0x1010, size=16)

        cfg.add_block(block1)
        cfg.add_block(block2)

        assert len(cfg.blocks) == 2
        assert cfg.entry_block == block1

        cfg.add_edge(0x1000, 0x1010)
        assert (0x1000, 0x1010) in cfg.edges


class TestDependencyAnalyzer:
    """Comprehensive tests for DependencyAnalyzer."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_analyze_dependencies(self, ls_elf):
        """Test analyzing dependencies."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            functions = binary.get_functions()

            if len(functions) > 0:
                addr = functions[0].get("offset", functions[0].get("addr", 0))
                instructions = binary.get_function_disasm(addr)

                if len(instructions) > 0:
                    analyzer = DependencyAnalyzer()
                    deps = analyzer.analyze_dependencies(instructions)

                    assert isinstance(deps, list)


class TestDiffAnalyzer:
    """Comprehensive tests for DiffAnalyzer."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_diff_analyzer(self, ls_elf, tmp_path):
        """Test diff analyzer."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        morphed_path = tmp_path / "ls_diff"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass(config={"probability": 0.5}))
            engine.run()
            engine.save(morphed_path)

        analyzer = DiffAnalyzer()
        diff = analyzer.compare(ls_elf, morphed_path)

        assert diff is not None

    def test_get_similarity_score(self, ls_elf, tmp_path):
        """Test getting similarity score."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        morphed_path = tmp_path / "ls_diff2"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(morphed_path)

        analyzer = DiffAnalyzer()
        analyzer.compare(ls_elf, morphed_path)
        score = analyzer.get_similarity_score()

        assert isinstance(score, float)
        assert 0 <= score <= 100

    def test_visualize_changes(self, ls_elf, tmp_path):
        """Test visualizing changes."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        morphed_path = tmp_path / "ls_metrics"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(morphed_path)

        analyzer = DiffAnalyzer()
        analyzer.compare(ls_elf, morphed_path)
        viz = analyzer.visualize_changes()

        assert isinstance(viz, str)
        assert len(viz) > 0

    def test_generate_report(self, ls_elf, tmp_path):
        """Test generating report."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        morphed_path = tmp_path / "ls_report"
        report_file = tmp_path / "report.txt"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(morphed_path)

        analyzer = DiffAnalyzer()
        analyzer.compare(ls_elf, morphed_path)
        analyzer.generate_report(report_file)

        assert report_file.exists()


class TestInvariantDetector:
    """Comprehensive tests for InvariantDetector."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_invariant_detector(self, ls_elf):
        """Test invariant detector."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            detector = InvariantDetector(binary)
            functions = binary.get_functions()

            if len(functions) > 0:
                addr = functions[0].get("offset", functions[0].get("addr", 0))
                if addr:
                    invariants = detector.detect_all_invariants(addr)
                    assert isinstance(invariants, list)

    def test_detect_invariants(self, ls_elf):
        """Test detecting stack balance invariants."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            detector = InvariantDetector(binary)
            functions = binary.get_functions()

            if len(functions) > 0:
                addr = functions[0].get("offset", functions[0].get("addr", 0))
                if addr:
                    invariants = detector.detect_stack_balance(addr)
                    assert isinstance(invariants, list)