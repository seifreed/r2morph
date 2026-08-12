"""
Comprehensive real tests for validation modules.
"""

import importlib.util
from pathlib import Path

import pytest

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


from r2morph import MorphEngine
from r2morph.mutations import NopInsertionPass
from r2morph.validation.fuzzer import FuzzResult, MutationFuzzer
from r2morph.validation.validator import BinaryValidator, ValidationResult


class TestBinaryValidatorComprehensive:
    """Comprehensive tests for BinaryValidator."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_validator_init(self):
        """Test BinaryValidator initialization."""
        validator = BinaryValidator(timeout=10)

        assert validator is not None
        assert validator.timeout == 10
        assert isinstance(validator.test_cases, list)

    def test_add_test_case(self):
        """Test adding test case."""
        validator = BinaryValidator()

        validator.add_test_case(args=["--version"], stdin="", expected_exitcode=0, description="Version test")

        assert len(validator.test_cases) == 1

    def test_validate_binaries(self, ls_elf, tmp_path):
        """Test validating binaries."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        morphed_path = tmp_path / "ls_validate"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(morphed_path)

        validator = BinaryValidator(timeout=5)
        validator.add_test_case(description="Basic test")

        result = validator.validate(ls_elf, morphed_path)

        assert isinstance(result, ValidationResult)
        assert hasattr(result, "passed")
        assert hasattr(result, "similarity_score")

    def test_validation_result(self):
        """Test ValidationResult dataclass."""
        result = ValidationResult(
            passed=True,
            original_output="test",
            mutated_output="test",
            original_exitcode=0,
            mutated_exitcode=0,
            errors=[],
            similarity_score=100.0,
        )

        assert result.passed is True
        assert result.similarity_score == 100.0


class TestMutationFuzzerComprehensive:
    """Comprehensive tests for MutationFuzzer."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_fuzzer_init(self):
        """Test MutationFuzzer initialization."""
        fuzzer = MutationFuzzer(num_tests=10, timeout=5)

        assert fuzzer is not None
        assert fuzzer.num_tests == 10
        assert fuzzer.timeout == 5

    def test_fuzz_binaries(self, ls_elf, tmp_path):
        """Test fuzzing binaries."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        morphed_path = tmp_path / "ls_fuzz"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(morphed_path)

        fuzzer = MutationFuzzer(num_tests=5, timeout=3)
        result = fuzzer.fuzz(ls_elf, morphed_path, input_type="ascii")

        assert isinstance(result, FuzzResult)
        assert result.total_tests == 5

    def test_fuzz_with_args(self, ls_elf, tmp_path):
        """Test fuzzing with arguments."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        morphed_path = tmp_path / "ls_fuzz_args"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(morphed_path)

        fuzzer = MutationFuzzer(num_tests=3, timeout=3)
        result = fuzzer.fuzz_with_args(ls_elf, morphed_path, arg_count=2)

        assert isinstance(result, FuzzResult)
        assert result.total_tests == 3

    def test_fuzz_result(self):
        """Test FuzzResult dataclass."""
        result = FuzzResult(total_tests=10, passed=8, failed=2, crashes=0, timeouts=0, validation_results=[])

        assert result.total_tests == 10
        assert result.passed == 8
        assert result.success_rate == 80.0
