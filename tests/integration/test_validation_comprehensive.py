"""
Comprehensive real tests for validation modules.
"""

import importlib.util
from pathlib import Path

import pytest

from tests.utils.assertions import expect

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


from r2morph import MorphEngine
from r2morph.mutations import NopInsertionPass
from r2morph.validation.fuzzer import FuzzResult, MutationFuzzer
from r2morph.validation.validator import BinaryValidator, ValidationResult

_EXPECTED_FUZZER_NUM_TESTS_10 = 10
_EXPECTED_FUZZER_TIMEOUT_5 = 5
_EXPECTED_RESULT_PASSED_8 = 8
_EXPECTED_RESULT_SIMILARITY_SCORE_100_0 = 100.0
_EXPECTED_RESULT_SUCCESS_RATE_80_0 = 80.0
_EXPECTED_RESULT_TOTAL_TESTS_10 = 10
_EXPECTED_RESULT_TOTAL_TESTS_3 = 3
_EXPECTED_RESULT_TOTAL_TESTS_5 = 5
_EXPECTED_VALIDATOR_TIMEOUT_10 = 10


class TestBinaryValidatorComprehensive:
    """Comprehensive tests for BinaryValidator."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_validator_init(self):
        """Test BinaryValidator initialization."""
        validator = BinaryValidator(timeout=10)

        expect(validator is not None)
        expect(validator.timeout == _EXPECTED_VALIDATOR_TIMEOUT_10)
        expect(isinstance(validator.test_cases, list))

    def test_add_test_case(self):
        """Test adding test case."""
        validator = BinaryValidator()

        validator.add_test_case(args=["--version"], stdin="", expected_exitcode=0, description="Version test")

        expect(len(validator.test_cases) == 1)

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

        expect(isinstance(result, ValidationResult))
        expect(hasattr(result, "passed"))
        expect(hasattr(result, "similarity_score"))

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

        expect(not (result.passed is not True))
        expect(result.similarity_score == _EXPECTED_RESULT_SIMILARITY_SCORE_100_0)


class TestMutationFuzzerComprehensive:
    """Comprehensive tests for MutationFuzzer."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_fuzzer_init(self):
        """Test MutationFuzzer initialization."""
        fuzzer = MutationFuzzer(num_tests=10, timeout=5)

        expect(fuzzer is not None)
        expect(fuzzer.num_tests == _EXPECTED_FUZZER_NUM_TESTS_10)
        expect(fuzzer.timeout == _EXPECTED_FUZZER_TIMEOUT_5)

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

        expect(isinstance(result, FuzzResult))
        expect(result.total_tests == _EXPECTED_RESULT_TOTAL_TESTS_5)

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

        expect(isinstance(result, FuzzResult))
        expect(result.total_tests == _EXPECTED_RESULT_TOTAL_TESTS_3)

    def test_fuzz_result(self):
        """Test FuzzResult dataclass."""
        result = FuzzResult(total_tests=10, passed=8, failed=2, crashes=0, timeouts=0, validation_results=[])

        expect(result.total_tests == _EXPECTED_RESULT_TOTAL_TESTS_10)
        expect(result.passed == _EXPECTED_RESULT_PASSED_8)
        expect(result.success_rate == _EXPECTED_RESULT_SUCCESS_RATE_80_0)
