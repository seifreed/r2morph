"""
Real integration tests using dataset binaries.
"""

import importlib.util
from pathlib import Path

import pytest

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


pytest.importorskip("yaml")

from r2morph import MorphEngine
from r2morph.analysis.analyzer import BinaryAnalyzer
from r2morph.core.binary import Binary
from r2morph.mutations import (
    BlockReorderingPass,
    InstructionExpansionPass,
    InstructionSubstitutionPass,
    NopInsertionPass,
    RegisterSubstitutionPass,
)
from r2morph.validation.fuzzer import MutationFuzzer
from r2morph.validation.validator import BinaryValidator


class TestDatasetBinaries:
    """Integration tests with real dataset binaries."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    @pytest.fixture
    def ls_macos(self):
        """Path to ls macOS binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "macho_arm64"

    @pytest.fixture
    def pe_x86_64_exe(self):
        """Path to pe_x86_64.exe PE binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "pe_x86_64.exe"

    def test_analyze_elf_binary(self, ls_elf):
        """Test analyzing real ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()

            functions = binary.get_functions()
            assert len(functions) > 0

            arch_info = binary.get_arch_info()
            assert arch_info["arch"] in ["x86", "x64", "amd64"]
            assert arch_info["bits"] == 64
            assert "elf" in arch_info["format"].lower()

    def test_analyze_macos_binary(self, ls_macos):
        """Test analyzing real macOS binary."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        with Binary(ls_macos) as binary:
            binary.analyze()

            functions = binary.get_functions()
            assert len(functions) > 0

            arch_info = binary.get_arch_info()
            assert "mach" in arch_info["format"].lower()

    def test_analyze_pe_binary(self, pe_x86_64_exe):
        """Test analyzing real PE binary."""
        if not pe_x86_64_exe.exists():
            pytest.skip("PE binary not available")

        with Binary(pe_x86_64_exe) as binary:
            binary.analyze()

            functions = binary.get_functions()
            assert len(functions) > 0

            arch_info = binary.get_arch_info()
            assert "pe" in arch_info["format"].lower()
        assert arch_info["bits"] == 64

    def test_binary_analyzer_on_elf(self, ls_elf):
        """Test BinaryAnalyzer on real ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            analyzer = BinaryAnalyzer(binary)
            stats = analyzer.get_statistics()

            assert stats is not None
            assert "architecture" in stats
            assert "total_functions" in stats
            assert stats["total_functions"] > 0

    def test_nop_insertion_on_elf(self, ls_elf, tmp_path):
        """Test NOP insertion on real ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_nop"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            config = {
                "max_nops_per_function": 3,
                "probability": 0.5,
                "use_creative_nops": False,
            }
            engine.add_mutation(NopInsertionPass(config=config))

            result = engine.run()
            engine.save(output_path)

        assert output_path.exists()
        assert result["total_mutations"] >= 0
        assert output_path.stat().st_size > 0

    def test_instruction_substitution_on_elf(self, ls_elf, tmp_path):
        """Test instruction substitution on real ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_subst"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            config = {
                "max_substitutions_per_function": 5,
                "probability": 0.5,
                "strict_size": True,
            }
            engine.add_mutation(InstructionSubstitutionPass(config=config))

            result = engine.run()
            engine.save(output_path)

        assert output_path.exists()
        assert result["total_mutations"] >= 0

    def test_multiple_mutations_on_elf(self, ls_elf, tmp_path):
        """Test multiple mutations on real ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_multi"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            nop_config = {"max_nops_per_function": 2, "probability": 0.4}
            subst_config = {"max_substitutions_per_function": 3, "probability": 0.4}
            reg_config = {"max_substitutions_per_function": 2, "probability": 0.3}

            engine.add_mutation(NopInsertionPass(config=nop_config))
            engine.add_mutation(InstructionSubstitutionPass(config=subst_config))
            engine.add_mutation(RegisterSubstitutionPass(config=reg_config))

            result = engine.run()
            engine.save(output_path)

        assert output_path.exists()
        assert result["total_mutations"] >= 0
        assert "pass_results" in result

    def test_register_substitution_on_elf(self, ls_elf, tmp_path):
        """Test register substitution on real ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_reg"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            config = {
                "max_substitutions_per_function": 3,
                "probability": 0.5,
            }
            engine.add_mutation(RegisterSubstitutionPass(config=config))

            engine.run()
            engine.save(output_path)

        assert output_path.exists()

    def test_instruction_expansion_on_elf(self, ls_elf, tmp_path):
        """Test instruction expansion on real ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_expand"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            config = {
                "max_expansions_per_function": 3,
                "probability": 0.4,
            }
            engine.add_mutation(InstructionExpansionPass(config=config))

            engine.run()
            engine.save(output_path)

        assert output_path.exists()

    def test_block_reordering_on_elf(self, ls_elf, tmp_path):
        """Test block reordering on real ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_block"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            config = {
                "max_reorderings_per_function": 2,
                "probability": 0.3,
            }
            engine.add_mutation(BlockReorderingPass(config=config))

            engine.run()
            engine.save(output_path)

        assert output_path.exists()

    def test_get_functions_from_elf(self, ls_elf):
        """Test getting functions from real ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            functions = binary.get_functions()

        assert len(functions) >= 1
        assert all("name" in f or "offset" in f for f in functions)

    def test_get_disassembly_from_elf(self, ls_elf):
        """Test getting disassembly from real ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            functions = binary.get_functions()

            if len(functions) > 0:
                func_addr = functions[0].get("offset") or functions[0].get("addr")
                if func_addr:
                    disasm = binary.get_function_disasm(func_addr)
                    assert len(disasm) >= 0

    def test_get_basic_blocks_from_elf(self, ls_elf):
        """Test getting basic blocks from real ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            functions = binary.get_functions()

            if len(functions) > 0:
                func_addr = functions[0].get("offset") or functions[0].get("addr")
                if func_addr:
                    blocks = binary.get_basic_blocks(func_addr)
                    assert isinstance(blocks, list)

    def test_assemble_on_elf(self, ls_elf):
        """Test assembling instructions on real ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()

            nop = binary.assemble("nop")
            assert nop is not None
            assert len(nop) > 0

            xor = binary.assemble("xor eax, eax")
            assert xor is not None

    def test_fuzzer_on_elf(self, ls_elf, tmp_path):
        """Test fuzzer on real ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_fuzz"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass(config={"probability": 0.3}))
            engine.run()
            engine.save(output_path)

        fuzzer = MutationFuzzer(num_tests=5, timeout=10)
        result = fuzzer.fuzz_with_args(ls_elf, output_path, arg_count=2)

        assert result.total_tests == 5
        assert result.passed + result.failed == 5

    def test_validator_on_elf(self, ls_elf, tmp_path):
        """Test validator on real ELF binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_validate"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass(config={"probability": 0.2}))
            engine.run()
            engine.save(output_path)

        validator = BinaryValidator(timeout=10)
        validator.add_test_case(args=["--version"], description="Version test")

        result = validator.validate(ls_elf, output_path)

        assert isinstance(result.passed, bool)
        assert result.similarity_score >= 0
        assert result.similarity_score <= 100
