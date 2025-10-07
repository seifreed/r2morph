"""
Real integration tests for validation using compiled binaries.
"""

from pathlib import Path

import pytest

from r2morph import MorphEngine
from r2morph.mutations import InstructionSubstitutionPass, NopInsertionPass
from r2morph.validation.fuzzer import MutationFuzzer
from r2morph.validation.validator import BinaryValidator


class TestRealValidation:
    """Integration tests for validation with real binaries."""

    @pytest.fixture
    def simple_binary(self):
        """Path to simple test binary."""
        return Path(__file__).parent.parent / "fixtures" / "simple"

    @pytest.fixture
    def loop_binary(self):
        """Path to loop test binary."""
        return Path(__file__).parent.parent / "fixtures" / "loop"

    def test_validator_with_real_binaries(self, simple_binary, tmp_path):
        """Test validator with real original and mutated binaries."""
        if not simple_binary.exists():
            pytest.skip("Test binary not available")

        mutated_path = tmp_path / "simple_validated"

        with MorphEngine() as engine:
            engine.load_binary(simple_binary).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(mutated_path)

        validator = BinaryValidator(timeout=5)
        validator.add_test_case(description="Default execution")

        result = validator.validate(simple_binary, mutated_path)

        assert result.passed is True
        assert result.similarity_score == 100.0
        assert result.original_exitcode == result.mutated_exitcode
        assert result.original_output == result.mutated_output

    def test_validator_multiple_test_cases(self, loop_binary, tmp_path):
        """Test validator with multiple test cases."""
        if not loop_binary.exists():
            pytest.skip("Test binary not available")

        mutated_path = tmp_path / "loop_validated"

        with MorphEngine() as engine:
            engine.load_binary(loop_binary).analyze()
            engine.add_mutation(InstructionSubstitutionPass())
            engine.run()
            engine.save(mutated_path)

        validator = BinaryValidator(timeout=5)
        validator.add_test_case(description="Test 1")
        validator.add_test_case(description="Test 2")
        validator.add_test_case(description="Test 3")

        result = validator.validate(loop_binary, mutated_path)

        assert result.passed is True
        assert len(result.errors) == 0

    def test_fuzzer_with_real_binaries(self, simple_binary, tmp_path):
        """Test fuzzer with real binaries."""
        if not simple_binary.exists():
            pytest.skip("Test binary not available")

        mutated_path = tmp_path / "simple_fuzzed"

        with MorphEngine() as engine:
            engine.load_binary(simple_binary).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(mutated_path)

        fuzzer = MutationFuzzer(num_tests=10, timeout=5)
        result = fuzzer.fuzz(simple_binary, mutated_path, input_type="ascii")

        assert result.total_tests == 10
        assert result.passed + result.failed == 10
        assert result.success_rate >= 0.0
        assert result.success_rate <= 100.0

    def test_fuzzer_with_args(self, loop_binary, tmp_path):
        """Test fuzzer with command-line arguments."""
        if not loop_binary.exists():
            pytest.skip("Test binary not available")

        mutated_path = tmp_path / "loop_fuzzed_args"

        with MorphEngine() as engine:
            engine.load_binary(loop_binary).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(mutated_path)

        fuzzer = MutationFuzzer(num_tests=5, timeout=5)
        result = fuzzer.fuzz_with_args(loop_binary, mutated_path, arg_count=3)

        assert result.total_tests == 5
        assert result.passed + result.failed == 5

    def test_validate_preserves_semantics(self, simple_binary, tmp_path):
        """Test that mutations preserve program semantics."""
        if not simple_binary.exists():
            pytest.skip("Test binary not available")

        mutated_path = tmp_path / "simple_semantics"

        with MorphEngine() as engine:
            engine.load_binary(simple_binary).analyze()

            config = {
                "max_nops_per_function": 10,
                "probability": 0.9,
            }
            engine.add_mutation(NopInsertionPass(config=config))

            result = engine.run()
            engine.save(mutated_path)

        assert result["total_mutations"] > 0

        validator = BinaryValidator()
        val_result = validator.validate(simple_binary, mutated_path)

        assert val_result.passed is True
        assert val_result.original_exitcode == 0
        assert val_result.mutated_exitcode == 0
