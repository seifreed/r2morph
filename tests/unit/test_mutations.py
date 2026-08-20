"""
Tests for mutation passes using real binaries.
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
from r2morph.mutations.block_reordering import BlockReorderingPass
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass
from r2morph.mutations.instruction_expansion import InstructionExpansionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass

_EXPECTED_CFF_PASS_MAX_FUNCTIONS_5 = 5
_EXPECTED_CFF_PASS_MIN_BLOCKS_3 = 3
_EXPECTED_LEN_EQUIVALENTS_2 = 2


class TestNopInsertionPass:
    """Test cases for NOP insertion mutation."""

    def test_nop_init(self):
        nop_pass = NopInsertionPass()
        expect(nop_pass.name == "NopInsertion")
        expect(nop_pass.config is not None)

    def test_nop_safe_self_redundancy_rejects_32bit_subregisters_on_x86_64(self):
        nop_pass = NopInsertionPass()

        expect(not (nop_pass._is_safe_self_redundancy("rax", 64) is not True))
        expect(not (nop_pass._is_safe_self_redundancy("rcx", 64) is not True))
        expect(not (nop_pass._is_safe_self_redundancy("eax", 64) is not False))
        expect(not (nop_pass._is_safe_self_redundancy("ecx", 64) is not False))
        expect(not (nop_pass._is_safe_self_redundancy("ebx", 64) is not False))

    def test_nop_apply(self, tmp_path):
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_nop"
        temp_binary.write_bytes(test_file.read_bytes())

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            nop_pass = NopInsertionPass(config={"probability": 0.2})
            result = nop_pass.apply(binary)

        expect(not (result["mutations_applied"] < 0))


class TestInstructionSubstitutionPass:
    """Test cases for instruction substitution."""

    def test_subst_init(self):
        pytest.importorskip("yaml")
        instruction_substitution_pass = importlib.import_module(
            "r2morph.mutations.instruction_substitution"
        ).InstructionSubstitutionPass

        subst_pass = instruction_substitution_pass()
        expect(subst_pass.name == "InstructionSubstitution")

    def test_subst_equivalence_lookup_exposes_group_metadata(self):
        pytest.importorskip("yaml")
        instruction_substitution_pass = importlib.import_module(
            "r2morph.mutations.instruction_substitution"
        ).InstructionSubstitutionPass

        subst_pass = instruction_substitution_pass()
        normalized, equivalents, group_idx = subst_pass._get_equivalents(
            {"disasm": "xor eax, eax"},
            "x86",
        )

        expect(normalized == "xor eax, eax")
        expect(isinstance(group_idx, int))
        expect(not (len(equivalents) < _EXPECTED_LEN_EQUIVALENTS_2))
        expect(not ("xor eax, eax" not in equivalents))
        expect(not ("sub eax, eax" not in equivalents))

    def test_subst_apply(self, tmp_path):
        pytest.importorskip("yaml")
        instruction_substitution_pass = importlib.import_module(
            "r2morph.mutations.instruction_substitution"
        ).InstructionSubstitutionPass

        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_subst"
        temp_binary.write_bytes(test_file.read_bytes())

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            subst_pass = instruction_substitution_pass(config={"probability": 0.2})
            result = subst_pass.apply(binary)

        expect(not (result["mutations_applied"] < 0))


class TestRegisterSubstitutionPass:
    """Test cases for register substitution."""

    def test_reg_init(self):
        reg_pass = RegisterSubstitutionPass()
        expect(reg_pass.name == "RegisterSubstitution")

    def test_reg_apply(self, tmp_path):
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_reg"
        temp_binary.write_bytes(test_file.read_bytes())

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            reg_pass = RegisterSubstitutionPass(config={"probability": 0.2})
            result = reg_pass.apply(binary)

        expect(not (result["mutations_applied"] < 0))


class TestInstructionExpansionPass:
    """Test cases for instruction expansion."""

    def test_expand_init(self):
        expand_pass = InstructionExpansionPass()
        expect(expand_pass.name == "InstructionExpansion")

    def test_expand_apply(self, tmp_path):
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_expand"
        temp_binary.write_bytes(test_file.read_bytes())

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            expand_pass = InstructionExpansionPass(config={"probability": 0.2})
            result = expand_pass.apply(binary)

        expect(not (result["mutations_applied"] < 0))


class TestBlockReorderingPass:
    """Test cases for block reordering."""

    def test_block_init(self):
        block_pass = BlockReorderingPass()
        expect(block_pass.name == "BlockReordering")

    def test_block_apply(self, tmp_path):
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_block"
        temp_binary.write_bytes(test_file.read_bytes())

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            block_pass = BlockReorderingPass(config={"probability": 0.2})
            result = block_pass.apply(binary)

        expect(not (result["mutations_applied"] < 0))


class TestControlFlowFlatteningPass:
    """Test cases for control flow flattening."""

    def test_cff_init(self):
        cff_pass = ControlFlowFlatteningPass()
        expect(cff_pass.name == "ControlFlowFlattening")
        expect(cff_pass.max_functions == _EXPECTED_CFF_PASS_MAX_FUNCTIONS_5)
        expect(cff_pass.min_blocks == _EXPECTED_CFF_PASS_MIN_BLOCKS_3)

    def test_cff_apply(self, tmp_path):
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_cff"
        temp_binary.write_bytes(test_file.read_bytes())

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            cff_pass = ControlFlowFlatteningPass(config={"probability": 0.2})
            result = cff_pass.apply(binary)

        expect(not ("mutations_applied" not in result))


class TestDeadCodeInjectionPass:
    """Test cases for dead code injection."""

    def test_dead_code_init(self):
        dc_pass = DeadCodeInjectionPass()
        expect(dc_pass.name == "DeadCodeInjection")

    def test_dead_code_apply(self, tmp_path):
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_deadcode"
        temp_binary.write_bytes(test_file.read_bytes())

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            dc_pass = DeadCodeInjectionPass(config={"probability": 0.2})
            result = dc_pass.apply(binary)

        expect(not ("mutations_applied" not in result))
        expect(not (result["mutations_applied"] < 0))
