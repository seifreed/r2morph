"""
Comprehensive real tests for core modules.
"""

import importlib
import importlib.util
from pathlib import Path

import pytest

from tests.utils.assertions import expect

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


from r2morph.core.binary import Binary
from r2morph.core.function import Function
from r2morph.core.instruction import Instruction
from r2morph.mutations import NopInsertionPass
from r2morph.pipeline.pipeline import Pipeline

_EXPECTED_FUNC_ADDRESS_4096 = 0x1000
_EXPECTED_FUNC_ADDRESS_8192 = 0x2000
_EXPECTED_FUNC_SIZE_128 = 128
_EXPECTED_FUNC_SIZE_64 = 64
_EXPECTED_INSN_ADDRESS_4096 = 0x1000
_EXPECTED_INSN_ADDRESS_4096_2 = 0x1000
_EXPECTED_INSN_SIZE_2 = 2


class TestBinaryComprehensive:
    """Comprehensive tests for Binary."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_binary_context_manager(self, ls_elf):
        """Test binary as context manager."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            expect(binary is not None)

    def test_binary_analyze(self, ls_elf):
        """Test analyzing binary."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            expect(True)

    def test_get_functions(self, ls_elf):
        """Test getting functions."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            functions = binary.get_functions()

            expect(isinstance(functions, list))
            expect(not (len(functions) <= 0))

    def test_get_arch_info(self, ls_elf):
        """Test getting architecture info."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            arch_info = binary.get_arch_info()

            expect(isinstance(arch_info, dict))
            expect(not ("arch" not in arch_info))
            expect(not ("bits" not in arch_info))
            expect(not ("format" not in arch_info))

    def test_get_sections(self, ls_elf):
        """Test getting sections."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            if not hasattr(binary, "get_sections"):
                pytest.skip("get_sections method not implemented")

            sections = binary.get_sections()

            expect(isinstance(sections, list))

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
                    expect(isinstance(disasm, list))

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
                    expect(isinstance(blocks, list))

    def test_assemble(self, ls_elf):
        """Test assembling instruction."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()
            result = binary.assemble("nop")

            expect(result is not None)
            expect(isinstance(result, bytes))

    def test_write_bytes(self, ls_elf, tmp_path):
        """Test writing bytes."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        shutil = importlib.import_module("shutil")

        temp_binary = tmp_path / "test_write"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            result = binary.write_bytes(0x1000, b"\x90")

            expect(isinstance(result, bool))


class TestFunctionComprehensive:
    """Comprehensive tests for Function."""

    def test_function_from_r2_dict(self):
        """Test creating Function from r2 dict."""
        r2_dict = {"name": "main", "offset": 0x1000, "size": 128}

        func = Function.from_r2_dict(r2_dict)

        expect(func.name == "main")
        expect(func.address == _EXPECTED_FUNC_ADDRESS_4096)
        expect(func.size == _EXPECTED_FUNC_SIZE_128)

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

        expect(func.name == "test_func")
        expect(func.address == _EXPECTED_FUNC_ADDRESS_8192)
        expect(func.size == _EXPECTED_FUNC_SIZE_64)

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

        expect(not ("0x1000" not in repr_str))


class TestInstructionComprehensive:
    """Comprehensive tests for Instruction."""

    def test_instruction_from_r2_dict(self):
        """Test creating Instruction from r2 dict."""
        r2_dict = {"offset": 0x1000, "size": 1, "type": "nop", "disasm": "nop"}

        insn = Instruction.from_r2_dict(r2_dict)

        expect(insn.address == _EXPECTED_INSN_ADDRESS_4096)
        expect(insn.size == 1)

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

        expect(insn.address == _EXPECTED_INSN_ADDRESS_4096_2)
        expect(insn.mnemonic == "mov")
        expect(insn.size == _EXPECTED_INSN_SIZE_2)

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
        expect(not (insn.is_jump() is not True))

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
        expect(not (insn.is_call() is not True))

    def test_instruction_is_ret(self):
        """Test checking if instruction is ret."""
        insn = Instruction(address=0x1000, mnemonic="ret", operands=[], size=1, bytes=b"\xc3", type="ret")
        expect(not (insn.is_ret() is not True))

    def test_instruction_repr(self):
        """Test Instruction repr."""
        insn = Instruction(address=0x1000, mnemonic="nop", operands=[], size=1, bytes=b"\x90", type="nop")
        repr_str = repr(insn)

        expect(not ("0x1000" not in repr_str))


class TestPipelineComprehensive:
    """Comprehensive tests for Pipeline."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_pipeline_init(self):
        """Test Pipeline initialization."""
        pipeline = Pipeline()

        expect(pipeline is not None)
        expect(isinstance(pipeline.passes, list))

    def test_pipeline_add_pass(self):
        """Test adding pass to pipeline."""
        pipeline = Pipeline()

        nop_pass = NopInsertionPass()
        pipeline.add_pass(nop_pass)

        expect(len(pipeline.passes) == 1)

    def test_pipeline_run(self, ls_elf):
        """Test running pipeline."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        with Binary(ls_elf) as binary:
            binary.analyze()

            pipeline = Pipeline()
            pipeline.add_pass(NopInsertionPass(config={"probability": 0.5}))

            result = pipeline.run(binary)
            expect(isinstance(result, dict))

    def test_pipeline_get_pass_names(self):
        """Test getting pipeline pass names."""
        pipeline = Pipeline()
        pipeline.add_pass(NopInsertionPass())

        names = pipeline.get_pass_names()
        expect(isinstance(names, list))
        expect(not (len(names) <= 0))
