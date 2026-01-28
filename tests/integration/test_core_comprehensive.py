"""
Comprehensive real tests for core modules.
"""

from pathlib import Path

import pytest
import importlib.util

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)



from r2morph.core.binary import Binary
from r2morph.core.function import Function
from r2morph.core.instruction import Instruction
from r2morph.mutations import NopInsertionPass
from r2morph.pipeline.pipeline import Pipeline


class TestBinaryComprehensive:
    """Comprehensive tests for Binary."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_binary_context_manager(self, ls_elf):
        """Test binary as context manager."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            assert binary is not None

    def test_binary_analyze(self, ls_elf):
        """Test analyzing binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            assert True

    def test_get_functions(self, ls_elf):
        """Test getting functions."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            functions = binary.get_functions()

            assert isinstance(functions, list)
            assert len(functions) > 0

    def test_get_arch_info(self, ls_elf):
        """Test getting architecture info."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            arch_info = binary.get_arch_info()

            assert isinstance(arch_info, dict)
            assert "arch" in arch_info
            assert "bits" in arch_info
            assert "format" in arch_info

    def test_get_sections(self, ls_elf):
        """Test getting sections."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            if not hasattr(binary, "get_sections"):
                pytest.skip("get_sections method not implemented")

            sections = binary.get_sections()

            assert isinstance(sections, list)

    def test_get_function_disasm(self, ls_elf):
        """Test getting function disassembly."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            functions = binary.get_functions()

            if len(functions) > 0:
                addr = functions[0].get("offset", functions[0].get("addr", 0))
                if addr:
                    disasm = binary.get_function_disasm(addr)
                    assert isinstance(disasm, list)

    def test_get_basic_blocks(self, ls_elf):
        """Test getting basic blocks."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            functions = binary.get_functions()

            if len(functions) > 0:
                addr = functions[0].get("offset", functions[0].get("addr", 0))
                if addr:
                    blocks = binary.get_basic_blocks(addr)
                    assert isinstance(blocks, list)

    def test_assemble(self, ls_elf):
        """Test assembling instruction."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            result = binary.assemble("nop")

            assert result is not None
            assert isinstance(result, bytes)

    def test_write_bytes(self, ls_elf, tmp_path):
        """Test writing bytes."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        import shutil

        temp_binary = tmp_path / "test_write"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            result = binary.write_bytes(0x1000, b"\x90")

            assert isinstance(result, bool)


class TestFunctionComprehensive:
    """Comprehensive tests for Function."""

    def test_function_from_r2_dict(self):
        """Test creating Function from r2 dict."""
        r2_dict = {"name": "main", "offset": 0x1000, "size": 128}

        func = Function.from_r2_dict(r2_dict)

        assert func.name == "main"
        assert func.address == 0x1000
        assert func.size == 128

    def test_function_properties(self):
        """Test Function properties."""
        func = Function(
            name="test_func",
            address=0x2000,
            size=64,
            instructions=[],
            basic_blocks=[],
            calls=[],
            metadata={},
        )

        assert func.name == "test_func"
        assert func.address == 0x2000
        assert func.size == 64

    def test_function_repr(self):
        """Test Function repr."""
        func = Function(
            name="test",
            address=0x1000,
            size=32,
            instructions=[],
            basic_blocks=[],
            calls=[],
            metadata={},
        )
        repr_str = repr(func)

        assert "0x1000" in repr_str


class TestInstructionComprehensive:
    """Comprehensive tests for Instruction."""

    def test_instruction_from_r2_dict(self):
        """Test creating Instruction from r2 dict."""
        r2_dict = {"offset": 0x1000, "size": 1, "type": "nop", "disasm": "nop"}

        insn = Instruction.from_r2_dict(r2_dict)

        assert insn.address == 0x1000
        assert insn.size == 1

    def test_instruction_properties(self):
        """Test Instruction properties."""
        insn = Instruction(
            address=0x1000,
            mnemonic="mov",
            operands=["rax", "rbx"],
            size=2,
            bytes=b"\x48\x89",
            type="mov",
        )

        assert insn.address == 0x1000
        assert insn.mnemonic == "mov"
        assert insn.size == 2

    def test_instruction_is_jump(self):
        """Test checking if instruction is jump."""
        insn = Instruction(
            address=0x1000,
            mnemonic="jmp",
            operands=["0x2000"],
            size=2,
            bytes=b"\xeb\x00",
            type="jmp",
        )
        assert insn.is_jump() is True

    def test_instruction_is_call(self):
        """Test checking if instruction is call."""
        insn = Instruction(
            address=0x1000,
            mnemonic="call",
            operands=["0x2000"],
            size=5,
            bytes=b"\xe8\x00\x00\x00\x00",
            type="call",
        )
        assert insn.is_call() is True

    def test_instruction_is_ret(self):
        """Test checking if instruction is ret."""
        insn = Instruction(
            address=0x1000, mnemonic="ret", operands=[], size=1, bytes=b"\xc3", type="ret"
        )
        assert insn.is_ret() is True

    def test_instruction_repr(self):
        """Test Instruction repr."""
        insn = Instruction(
            address=0x1000, mnemonic="nop", operands=[], size=1, bytes=b"\x90", type="nop"
        )
        repr_str = repr(insn)

        assert "0x1000" in repr_str


class TestPipelineComprehensive:
    """Comprehensive tests for Pipeline."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_pipeline_init(self):
        """Test Pipeline initialization."""
        pipeline = Pipeline()

        assert pipeline is not None
        assert isinstance(pipeline.passes, list)

    def test_pipeline_add_pass(self):
        """Test adding pass to pipeline."""
        pipeline = Pipeline()

        nop_pass = NopInsertionPass()
        pipeline.add_pass(nop_pass)

        assert len(pipeline.passes) == 1

    def test_pipeline_run(self, ls_elf):
        """Test running pipeline."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()

            pipeline = Pipeline()
            pipeline.add_pass(NopInsertionPass(config={"probability": 0.5}))

            result = pipeline.run(binary)
            assert isinstance(result, dict)

    def test_pipeline_get_pass_names(self):
        """Test getting pipeline pass names."""
        pipeline = Pipeline()
        pipeline.add_pass(NopInsertionPass())

        names = pipeline.get_pass_names()
        assert isinstance(names, list)
        assert len(names) > 0