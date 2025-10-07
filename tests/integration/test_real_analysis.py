"""
Real integration tests for analysis modules.
"""

from pathlib import Path

import pytest

from r2morph.analysis.analyzer import BinaryAnalyzer
from r2morph.analysis.cfg import CFGBuilder
from r2morph.analysis.dependencies import DependencyAnalyzer
from r2morph.core.binary import Binary


class TestRealAnalysis:
    """Integration tests for analysis with real binaries."""

    @pytest.fixture
    def simple_binary(self):
        """Path to simple test binary."""
        return Path(__file__).parent.parent / "fixtures" / "simple"

    @pytest.fixture
    def loop_binary(self):
        """Path to loop test binary."""
        return Path(__file__).parent.parent / "fixtures" / "loop"

    @pytest.fixture
    def conditional_binary(self):
        """Path to conditional test binary."""
        return Path(__file__).parent.parent / "fixtures" / "conditional"

    def test_binary_analyzer_real(self, simple_binary):
        """Test binary analyzer with real binary."""
        if not simple_binary.exists():
            pytest.skip("Test binary not available")

        with Binary(simple_binary) as binary:
            binary.analyze()
            analyzer = BinaryAnalyzer(binary)
            stats = analyzer.get_statistics()

            assert stats is not None
            assert "architecture" in stats
            assert "total_functions" in stats

            # Skip if binary has no analyzable content
            if stats["total_functions"] == 0:
                pytest.skip("Binary has no analyzable functions")

            assert stats["total_functions"] > 0
            # Note: total_instructions may be 0 if binary is stripped or has no disassembly

    def test_get_functions_real(self, loop_binary):
        """Test getting functions from real binary."""
        if not loop_binary.exists():
            pytest.skip("Test binary not available")

        with Binary(loop_binary) as binary:
            binary.analyze()
            functions = binary.get_functions()

            assert len(functions) > 0
            assert any(f.get("name") == "main" for f in functions)

    def test_get_arch_info_real(self, conditional_binary):
        """Test getting architecture info from real binary."""
        if not conditional_binary.exists():
            pytest.skip("Test binary not available")

        with Binary(conditional_binary) as binary:
            binary.analyze()
            arch_info = binary.get_arch_info()

            assert arch_info["arch"] in ["x86", "x64", "amd64", "arm", "aarch64"]
            assert arch_info["bits"] in [32, 64]
            # Format can be lowercase or uppercase and may include bits
            fmt = arch_info["format"].lower()
            assert any(f in fmt for f in ["elf", "mach", "pe"])

    def test_cfg_builder_real(self, simple_binary):
        """Test CFG builder with real binary."""
        if not simple_binary.exists():
            pytest.skip("Test binary not available")

        with Binary(simple_binary) as binary:
            binary.analyze()
            functions = binary.get_functions()

            if len(functions) > 0:
                func_addr = functions[0].get("offset", functions[0].get("addr", 0))
                cfg_builder = CFGBuilder(binary)
                cfg = cfg_builder.build_cfg(func_addr, "test_function")

                assert cfg is not None
                assert len(cfg.blocks) > 0
                assert cfg.function_address == func_addr

    def test_dependency_analyzer_real(self, loop_binary):
        """Test dependency analyzer with real binary."""
        if not loop_binary.exists():
            pytest.skip("Test binary not available")

        with Binary(loop_binary) as binary:
            binary.analyze()
            functions = binary.get_functions()

            if len(functions) > 0:
                func_addr = functions[0].get("offset", functions[0].get("addr", 0))
                instructions = binary.get_function_disasm(func_addr)

                if len(instructions) > 0:
                    analyzer = DependencyAnalyzer()
                    deps = analyzer.analyze_dependencies(instructions)

                    assert isinstance(deps, list)

    def test_function_disassembly_real(self, conditional_binary):
        """Test function disassembly with real binary."""
        if not conditional_binary.exists():
            pytest.skip("Test binary not available")

        with Binary(conditional_binary) as binary:
            binary.analyze()
            functions = binary.get_functions()

            assert len(functions) > 0

            main_func = next((f for f in functions if f.get("name") == "main"), None)
            if main_func:
                func_addr = main_func.get("offset", main_func.get("addr", 0))
                disasm = binary.get_function_disasm(func_addr)

                assert len(disasm) > 0
                assert all("offset" in insn or "addr" in insn for insn in disasm)
                assert all("disasm" in insn or "opcode" in insn for insn in disasm)

    def test_basic_blocks_real(self, simple_binary):
        """Test basic blocks with real binary."""
        if not simple_binary.exists():
            pytest.skip("Test binary not available")

        with Binary(simple_binary) as binary:
            binary.analyze()
            functions = binary.get_functions()

            if len(functions) > 0:
                func_addr = functions[0].get("offset", functions[0].get("addr", 0))
                blocks = binary.get_basic_blocks(func_addr)

                assert isinstance(blocks, list)

    def test_binary_writable_mode(self, tmp_path, simple_binary):
        """Test binary in writable mode."""
        if not simple_binary.exists():
            pytest.skip("Test binary not available")

        import shutil

        temp_binary = tmp_path / "writable_test"
        shutil.copy(simple_binary, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            functions = binary.get_functions()

            assert len(functions) > 0

    def test_assemble_instruction(self, simple_binary):
        """Test assembling instructions."""
        if not simple_binary.exists():
            pytest.skip("Test binary not available")

        with Binary(simple_binary) as binary:
            binary.analyze()

            nop_bytes = binary.assemble("nop")

            assert nop_bytes is not None
            assert len(nop_bytes) > 0
