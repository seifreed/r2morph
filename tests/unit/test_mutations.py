"""
Tests for mutation passes using real binaries.
"""

import importlib.util
from pathlib import Path

import pytest

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


class TestNopInsertionPass:
    """Test cases for NOP insertion mutation."""

    def test_nop_init(self):
        nop_pass = NopInsertionPass()
        assert nop_pass.name == "NopInsertion"
        assert nop_pass.config is not None

    def test_nop_apply(self, tmp_path):
        test_file = Path(__file__).parent.parent / "fixtures" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_nop"
        temp_binary.write_bytes(test_file.read_bytes())

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            nop_pass = NopInsertionPass(config={"probability": 0.2})
            result = nop_pass.apply(binary)

        assert result["mutations_applied"] >= 0


class TestInstructionSubstitutionPass:
    """Test cases for instruction substitution."""

    def test_subst_init(self):
        pytest.importorskip("yaml")
        from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
        subst_pass = InstructionSubstitutionPass()
        assert subst_pass.name == "InstructionSubstitution"

    def test_subst_apply(self, tmp_path):
        pytest.importorskip("yaml")
        from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
        test_file = Path(__file__).parent.parent / "fixtures" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_subst"
        temp_binary.write_bytes(test_file.read_bytes())

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            subst_pass = InstructionSubstitutionPass(config={"probability": 0.2})
            result = subst_pass.apply(binary)

        assert result["mutations_applied"] >= 0


class TestRegisterSubstitutionPass:
    """Test cases for register substitution."""

    def test_reg_init(self):
        reg_pass = RegisterSubstitutionPass()
        assert reg_pass.name == "RegisterSubstitution"

    def test_reg_apply(self, tmp_path):
        test_file = Path(__file__).parent.parent / "fixtures" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_reg"
        temp_binary.write_bytes(test_file.read_bytes())

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            reg_pass = RegisterSubstitutionPass(config={"probability": 0.2})
            result = reg_pass.apply(binary)

        assert result["mutations_applied"] >= 0


class TestInstructionExpansionPass:
    """Test cases for instruction expansion."""

    def test_expand_init(self):
        expand_pass = InstructionExpansionPass()
        assert expand_pass.name == "InstructionExpansion"

    def test_expand_apply(self, tmp_path):
        test_file = Path(__file__).parent.parent / "fixtures" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_expand"
        temp_binary.write_bytes(test_file.read_bytes())

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            expand_pass = InstructionExpansionPass(config={"probability": 0.2})
            result = expand_pass.apply(binary)

        assert result["mutations_applied"] >= 0


class TestBlockReorderingPass:
    """Test cases for block reordering."""

    def test_block_init(self):
        block_pass = BlockReorderingPass()
        assert block_pass.name == "BlockReordering"

    def test_block_apply(self, tmp_path):
        test_file = Path(__file__).parent.parent / "fixtures" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_block"
        temp_binary.write_bytes(test_file.read_bytes())

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            block_pass = BlockReorderingPass(config={"probability": 0.2})
            result = block_pass.apply(binary)

        assert result["mutations_applied"] >= 0


class TestControlFlowFlatteningPass:
    """Test cases for control flow flattening."""

    def test_cff_init(self):
        cff_pass = ControlFlowFlatteningPass()
        assert cff_pass.name == "ControlFlowFlattening"
        assert cff_pass.max_functions == 5
        assert cff_pass.min_blocks == 3

    def test_cff_apply(self, tmp_path):
        test_file = Path(__file__).parent.parent / "fixtures" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_cff"
        temp_binary.write_bytes(test_file.read_bytes())

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            cff_pass = ControlFlowFlatteningPass(config={"probability": 0.2})
            result = cff_pass.apply(binary)

        assert "mutations_applied" in result


class TestDeadCodeInjectionPass:
    """Test cases for dead code injection."""

    def test_dead_code_init(self):
        dc_pass = DeadCodeInjectionPass()
        assert dc_pass.name == "DeadCodeInjection"

    def test_dead_code_apply(self, tmp_path):
        test_file = Path(__file__).parent.parent / "fixtures" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_deadcode"
        temp_binary.write_bytes(test_file.read_bytes())

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            dc_pass = DeadCodeInjectionPass(config={"probability": 0.2})
            result = dc_pass.apply(binary)

        assert "mutations_applied" in result
        assert result["mutations_applied"] >= 0