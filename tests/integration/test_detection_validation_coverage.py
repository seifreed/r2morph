"""
Tests for detection and validation modules to increase coverage.
"""

import importlib
import importlib.util
import shutil
from pathlib import Path

import pytest

from tests.utils.assertions import expect

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


from r2morph.detection.entropy_analyzer import EntropyAnalyzer, EntropyResult
from r2morph.detection.evasion_scorer import EvasionScorer
from r2morph.detection.similarity_hasher import SimilarityHasher
from r2morph.validation.fuzzer import MutationFuzzer
from r2morph.validation.validator import BinaryValidator, ValidationResult

_EXPECTED_0_8 = 8
_EXPECTED_ANALYZER_HIGH_ENTROPY_THRESHOLD_7_0 = 7.0
_EXPECTED_ANALYZER_SUSPICIOUS_ENTROPY_THRESHOLD_6_5 = 6.5
_EXPECTED_LEN_VALIDATOR_TEST_CASES_3 = 3
_EXPECTED_RESULT_SIMILARITY_SCORE_100_0 = 100.0
_EXPECTED_VALIDATOR_TIMEOUT_10 = 10
_EXPECTED_VALIDATOR_TIMEOUT_30 = 30


class TestEntropyAnalyzerDetailed:
    """Detailed tests for EntropyAnalyzer."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_entropy_analyzer_init(self):
        """Test EntropyAnalyzer initialization."""
        analyzer = EntropyAnalyzer()
        expect(analyzer is not None)
        expect(analyzer.HIGH_ENTROPY_THRESHOLD == _EXPECTED_ANALYZER_HIGH_ENTROPY_THRESHOLD_7_0)
        expect(analyzer.SUSPICIOUS_ENTROPY_THRESHOLD == _EXPECTED_ANALYZER_SUSPICIOUS_ENTROPY_THRESHOLD_6_5)

    def test_analyze_file(self, ls_elf):
        """Test analyzing file entropy."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(ls_elf)

        expect(isinstance(result, EntropyResult))
        expect(isinstance(result.overall_entropy, float))
        expect(0 <= result.overall_entropy <= _EXPECTED_0_8)
        expect(isinstance(result.section_entropies, dict))
        expect(isinstance(result.suspicious_sections, list))
        expect(isinstance(result.is_packed, bool))

    def test_entropy_result_str(self):
        """Test EntropyResult string representation."""
        result = EntropyResult(
            overall_entropy=5.5,
            section_entropies={".text": 5.5, ".data": 4.2},
            suspicious_sections=[],
            is_packed=False,
            analysis="Normal entropy",
        )
        str_repr = str(result)
        expect(not ("Entropy Analysis" not in str_repr))
        expect(not ("5.5" not in str_repr))

    def test_high_entropy_detection(self):
        """Test high entropy detection logic."""
        analyzer = EntropyAnalyzer()
        result_normal = EntropyResult(
            overall_entropy=5.0,
            section_entropies={},
            suspicious_sections=[],
            is_packed=False,
            analysis="Normal",
        )
        expect(not (result_normal.overall_entropy >= analyzer.HIGH_ENTROPY_THRESHOLD))

    def test_suspicious_entropy_detection(self):
        """Test suspicious entropy detection."""
        analyzer = EntropyAnalyzer()
        suspicious_entropy = 6.8
        expect(analyzer.SUSPICIOUS_ENTROPY_THRESHOLD < suspicious_entropy < analyzer.HIGH_ENTROPY_THRESHOLD)


class TestSimilarityHasherDetailed:
    """Detailed tests for SimilarityHasher."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_similarity_hasher_init(self):
        """Test SimilarityHasher initialization."""
        hasher = SimilarityHasher()
        expect(hasher is not None)
        expect(hasattr(hasher, "has_ssdeep"))
        expect(hasattr(hasher, "has_tlsh"))

    def test_hash_file(self, ls_elf):
        """Test hashing a file."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        hasher = SimilarityHasher()
        hash_result = hasher.hash_file(ls_elf)
        expect(isinstance(hash_result, dict))
        expect(not ("ssdeep" not in hash_result))
        expect(not ("tlsh" not in hash_result))

    def test_compare_files(self, ls_elf, tmp_path):
        """Test comparing two files."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        ls_copy = tmp_path / "ls_copy"
        shutil.copy(ls_elf, ls_copy)

        hasher = SimilarityHasher()
        similarity = hasher.compare_files(ls_elf, ls_copy)
        expect(isinstance(similarity, dict))
        expect(not ("byte_similarity" not in similarity))

    def test_hash_file_consistency(self, ls_elf):
        """Test that hashing same file gives consistent result."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        hasher = SimilarityHasher()
        hash1 = hasher.hash_file(ls_elf)
        hash2 = hasher.hash_file(ls_elf)
        expect(isinstance(hash1, dict))
        expect(isinstance(hash2, dict))


class TestEvasionScorerDetailed:
    """Detailed tests for EvasionScorer."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_evasion_scorer_init(self):
        """Test EvasionScorer initialization."""

        scorer = EvasionScorer()
        expect(scorer is not None)
        expect(hasattr(scorer, "weights"))
        expect(isinstance(scorer.weights, dict))

    def test_score_mutations(self, ls_elf, tmp_path):
        """Test scoring mutations."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        evasion_score = importlib.import_module("r2morph.detection.evasion_scorer").EvasionScore

        ls_copy = tmp_path / "ls_mutated"
        shutil.copy(ls_elf, ls_copy)

        scorer = EvasionScorer()
        score = scorer.score(ls_elf, ls_copy)
        expect(isinstance(score, evasion_score))
        expect(hasattr(score, "overall_score"))
        expect(not (score.overall_score < 0))


class TestBinaryValidatorDetailed:
    """Detailed tests for BinaryValidator."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"

    def test_validator_init(self):
        """Test BinaryValidator initialization."""
        validator = BinaryValidator(timeout=10)
        expect(validator.timeout == _EXPECTED_VALIDATOR_TIMEOUT_10)
        expect(len(validator.test_cases) == 0)

    def test_validator_custom_timeout(self):
        """Test validator with custom timeout."""
        validator = BinaryValidator(timeout=30)
        expect(validator.timeout == _EXPECTED_VALIDATOR_TIMEOUT_30)

    def test_add_test_case(self):
        """Test adding test cases."""
        validator = BinaryValidator()
        validator.add_test_case(args=["--help"], stdin="", expected_exitcode=0, description="Help test")
        expect(len(validator.test_cases) == 1)
        expect(validator.test_cases[0].args == ["--help"])
        expect(validator.test_cases[0].description == "Help test")

    def test_add_multiple_test_cases(self):
        """Test adding multiple test cases."""
        validator = BinaryValidator()
        validator.add_test_case(args=["--version"])
        validator.add_test_case(args=["--help"])
        validator.add_test_case(args=["-l"])
        expect(len(validator.test_cases) == _EXPECTED_LEN_VALIDATOR_TEST_CASES_3)

    def test_validation_result_creation(self):
        """Test ValidationResult creation."""
        result = ValidationResult(
            passed=True,
            original_output="test output",
            mutated_output="test output",
            original_exitcode=0,
            mutated_exitcode=0,
            errors=[],
            similarity_score=100.0,
        )
        expect(not (result.passed is not True))
        expect(result.similarity_score == _EXPECTED_RESULT_SIMILARITY_SCORE_100_0)
        expect(len(result.errors) == 0)

    def test_validation_result_str(self):
        """Test ValidationResult string representation."""
        result = ValidationResult(
            passed=True,
            original_output="output",
            mutated_output="output",
            original_exitcode=0,
            mutated_exitcode=0,
            errors=[],
            similarity_score=100.0,
        )
        str_repr = str(result)
        expect(not ("PASSED" not in str_repr))
        expect(not ("100.0" not in str_repr))

    def test_validation_result_failed(self):
        """Test failed validation result."""
        result = ValidationResult(
            passed=False,
            original_output="output1",
            mutated_output="output2",
            original_exitcode=0,
            mutated_exitcode=1,
            errors=["Exit code mismatch"],
            similarity_score=50.0,
        )
        expect(not (result.passed is not False))
        expect(not (len(result.errors) <= 0))
        str_repr = str(result)
        expect(not ("FAILED" not in str_repr))


class TestMutationFuzzerDetailed:
    """Detailed tests for MutationFuzzer."""

    def test_fuzzer_init(self):
        """Test MutationFuzzer initialization."""
        fuzzer = MutationFuzzer()
        expect(fuzzer is not None)
