"""
Comprehensive real tests for mutation modules using dataset binaries.
"""

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations import (
    BlockReorderingPass,
    InstructionExpansionPass,
    InstructionSubstitutionPass,
    NopInsertionPass,
    RegisterSubstitutionPass,
)
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass
from r2morph.mutations.opaque_predicates import OpaquePredicatePass


class TestMutationsComprehensiveReal:
    """Comprehensive real tests for all mutations."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_dead_code_injection_basic(self, ls_elf, tmp_path):
        """Test dead code injection."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_dead_code"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = DeadCodeInjectionPass(
                config={"max_injections_per_function": 3, "probability": 1.0}
            )

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert "mutations_applied" in result

    def test_dead_code_injection_patterns(self, ls_elf, tmp_path):
        """Test dead code injection with different patterns."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_dead_code_patterns"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = DeadCodeInjectionPass(
                config={"max_injections_per_function": 5, "probability": 0.8}
            )

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)

    def test_opaque_predicate_basic(self, ls_elf, tmp_path):
        """Test opaque predicate insertion."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_opaque"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = OpaquePredicatePass(
                config={"max_predicates_per_function": 2, "probability": 1.0}
            )

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert "mutations_applied" in result

    def test_opaque_predicate_types(self, ls_elf, tmp_path):
        """Test different types of opaque predicates."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_opaque_types"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = OpaquePredicatePass(
                config={"max_predicates_per_function": 3, "probability": 0.8}
            )

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)

    def test_control_flow_flattening_basic(self, ls_elf, tmp_path):
        """Test control flow flattening."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_flatten"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = ControlFlowFlatteningPass(
                config={"max_functions_to_flatten": 2, "probability": 1.0}
            )

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert "mutations_applied" in result

    def test_control_flow_flattening_dispatcher(self, ls_elf, tmp_path):
        """Test control flow flattening with dispatcher."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_flatten_dispatch"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = ControlFlowFlatteningPass(
                config={"max_functions_to_flatten": 1, "probability": 1.0}
            )

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)

    def test_register_substitution_comprehensive(self, ls_elf, tmp_path):
        """Test comprehensive register substitution."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_reg_subst"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = RegisterSubstitutionPass(
                config={"max_substitutions_per_function": 5, "probability": 1.0}
            )

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert "mutations_applied" in result

    def test_instruction_expansion_comprehensive(self, ls_elf, tmp_path):
        """Test comprehensive instruction expansion."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_expand"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = InstructionExpansionPass(
                config={"max_expansions_per_function": 5, "probability": 1.0}
            )

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert "mutations_applied" in result

    def test_block_reordering_comprehensive(self, ls_elf, tmp_path):
        """Test comprehensive block reordering."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_reorder"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = BlockReorderingPass(
                config={"max_reorderings_per_function": 3, "probability": 1.0}
            )

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            assert "mutations_applied" in result

    def test_combined_mutations(self, ls_elf, tmp_path):
        """Test applying multiple mutations together."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_combined"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            mutations = [
                NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0}),
                InstructionSubstitutionPass(
                    config={"max_substitutions_per_function": 3, "probability": 1.0}
                ),
                RegisterSubstitutionPass(
                    config={"max_substitutions_per_function": 2, "probability": 1.0}
                ),
            ]

            for mutation in mutations:
                result = mutation.apply(binary)
                assert isinstance(result, dict)

    def test_mutations_with_low_probability(self, ls_elf, tmp_path):
        """Test mutations with low probability."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_low_prob"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            mutations = [
                NopInsertionPass(config={"max_nops_per_function": 5, "probability": 0.1}),
                DeadCodeInjectionPass(
                    config={"max_injections_per_function": 3, "probability": 0.1}
                ),
                OpaquePredicatePass(config={"max_predicates_per_function": 2, "probability": 0.1}),
            ]

            for mutation in mutations:
                result = mutation.apply(binary)
                assert isinstance(result, dict)

    def test_mutations_error_handling(self, ls_elf, tmp_path):
        """Test mutation error handling."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        temp_binary = tmp_path / "ls_errors"
        shutil.copy(ls_elf, temp_binary)

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()

            pass_obj = NopInsertionPass(config={"max_nops_per_function": 100, "probability": 1.0})

            result = pass_obj.apply(binary)
            assert isinstance(result, dict)
            # Just check the result is valid
            assert "mutations_applied" in result
