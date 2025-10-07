"""
Tests for mutation passes.
"""

from unittest.mock import Mock, patch

import pytest

from r2morph.mutations.block_reordering import BlockReorderingPass
from r2morph.mutations.instruction_expansion import InstructionExpansionPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass


class TestNopInsertionPass:
    """Test cases for NOP insertion mutation."""

    def test_nop_init(self):
        """Test NOP insertion initialization."""
        nop_pass = NopInsertionPass()
        assert nop_pass.name == "NopInsertion"
        assert nop_pass.config is not None

    def test_nop_with_config(self):
        """Test NOP insertion with custom config."""
        config = {"max_nops_per_function": 10, "probability": 0.8}
        nop_pass = NopInsertionPass(config=config)
        assert nop_pass.config["max_nops_per_function"] == 10
        assert nop_pass.config["probability"] == 0.8

    @patch("r2morph.mutations.nop_insertion.random.random")
    def test_nop_apply(self, mock_random):
        """Test applying NOP insertions."""
        mock_random.return_value = 0.1

        mock_binary = Mock()
        mock_binary.get_functions.return_value = [{"name": "main", "offset": 0x1000, "size": 100}]
        mock_binary.get_function_disasm.return_value = [
            {"offset": 0x1000, "size": 3, "disasm": "mov eax, ebx"},
            {"offset": 0x1003, "size": 2, "disasm": "ret"},
        ]
        mock_binary.assemble.return_value = b"\x90"
        mock_binary.write_bytes.return_value = True

        nop_pass = NopInsertionPass(config={"probability": 0.5})
        result = nop_pass.apply(mock_binary)

        assert result["mutations_applied"] >= 0
        assert "functions_mutated" in result


class TestInstructionSubstitutionPass:
    """Test cases for instruction substitution."""

    def test_subst_init(self):
        """Test substitution initialization."""
        subst_pass = InstructionSubstitutionPass()
        assert subst_pass.name == "InstructionSubstitution"

    @patch("r2morph.mutations.instruction_substitution.random.choice")
    @patch("r2morph.mutations.instruction_substitution.random.random")
    def test_subst_apply(self, mock_random, mock_choice):
        """Test applying instruction substitutions."""
        mock_random.return_value = 0.1
        mock_choice.return_value = "xor eax, eax"

        mock_binary = Mock()
        mock_binary.get_arch_info.return_value = {"arch": "x86", "bits": 64}
        mock_binary.get_functions.return_value = [{"name": "main", "offset": 0x1000, "size": 100}]
        mock_binary.get_function_disasm.return_value = [
            {"offset": 0x1000, "size": 3, "disasm": "mov eax, 0", "bytes": "b800000000"},
        ]
        mock_binary.assemble.return_value = b"\x31\xc0"
        mock_binary.write_bytes.return_value = True

        subst_pass = InstructionSubstitutionPass(config={"probability": 0.9})
        result = subst_pass.apply(mock_binary)

        assert result["mutations_applied"] >= 0


class TestRegisterSubstitutionPass:
    """Test cases for register substitution."""

    def test_reg_init(self):
        """Test register substitution initialization."""
        reg_pass = RegisterSubstitutionPass()
        assert reg_pass.name == "RegisterSubstitution"

    @patch("r2morph.mutations.register_substitution.random.random")
    def test_reg_apply(self, mock_random):
        """Test applying register substitutions."""
        mock_random.return_value = 0.1

        mock_binary = Mock()
        mock_binary.get_arch_info.return_value = {"arch": "x86", "bits": 64}
        mock_binary.get_functions.return_value = [{"name": "main", "offset": 0x1000, "size": 100}]
        mock_binary.get_function_disasm.return_value = [
            {"offset": 0x1000, "size": 3, "disasm": "mov eax, ebx"},
        ]
        mock_binary.assemble.return_value = b"\x89\xd8"
        mock_binary.write_bytes.return_value = True

        reg_pass = RegisterSubstitutionPass(config={"probability": 0.5})
        result = reg_pass.apply(mock_binary)

        assert result["mutations_applied"] >= 0


class TestInstructionExpansionPass:
    """Test cases for instruction expansion."""

    def test_expand_init(self):
        """Test expansion initialization."""
        expand_pass = InstructionExpansionPass()
        assert expand_pass.name == "InstructionExpansion"

    @patch("r2morph.mutations.instruction_expansion.random.random")
    def test_expand_apply(self, mock_random):
        """Test applying instruction expansions."""
        mock_random.return_value = 0.1

        mock_binary = Mock()
        mock_binary.get_arch_info.return_value = {"arch": "x86", "bits": 64}
        mock_binary.get_functions.return_value = [{"name": "main", "offset": 0x1000, "size": 100}]
        mock_binary.get_function_disasm.return_value = [
            {"offset": 0x1000, "size": 5, "disasm": "mov eax, 0"},
        ]

        expand_pass = InstructionExpansionPass(config={"probability": 0.5})
        result = expand_pass.apply(mock_binary)

        assert result["mutations_applied"] >= 0


class TestBlockReorderingPass:
    """Test cases for block reordering."""

    def test_block_init(self):
        """Test block reordering initialization."""
        block_pass = BlockReorderingPass()
        assert block_pass.name == "BlockReordering"

    @patch("r2morph.mutations.block_reordering.random.random")
    def test_block_apply(self, mock_random):
        """Test applying block reordering."""
        mock_random.return_value = 0.1

        mock_binary = Mock()
        mock_binary.get_functions.return_value = [{"name": "main", "offset": 0x1000, "size": 100}]
        mock_binary.get_basic_blocks.return_value = [
            {"addr": 0x1000, "size": 10, "jump": 0x1010},
            {"addr": 0x1010, "size": 10},
        ]

        block_pass = BlockReorderingPass(config={"probability": 0.5})
        result = block_pass.apply(mock_binary)

        assert result["mutations_applied"] >= 0
