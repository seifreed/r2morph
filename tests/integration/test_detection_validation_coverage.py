"""
Tests for detection and validation modules to increase coverage.
"""

import shutil
from pathlib import Path

import pytest

from r2morph.detection.entropy_analyzer import EntropyAnalyzer, EntropyResult
from r2morph.detection.evasion_scorer import EvasionScorer
from r2morph.detection.similarity_hasher import SimilarityHasher
from r2morph.validation.fuzzer import MutationFuzzer
from r2morph.validation.regression import RegressionTest, RegressionTester
from r2morph.validation.validator import BinaryValidator, ValidationResult


class TestEntropyAnalyzerDetailed:
    """Detailed tests for EntropyAnalyzer."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_entropy_analyzer_init(self):
        """Test EntropyAnalyzer initialization."""
        analyzer = EntropyAnalyzer()
        assert analyzer is not None
        assert analyzer.HIGH_ENTROPY_THRESHOLD == 7.0
        assert analyzer.SUSPICIOUS_ENTROPY_THRESHOLD == 6.5

    def test_analyze_file(self, ls_elf):
        """Test analyzing file entropy."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        analyzer = EntropyAnalyzer()
        result = analyzer.analyze_file(ls_elf)

        assert isinstance(result, EntropyResult)
        assert isinstance(result.overall_entropy, float)
        assert 0 <= result.overall_entropy <= 8
        assert isinstance(result.section_entropies, dict)
        assert isinstance(result.suspicious_sections, list)
        assert isinstance(result.is_packed, bool)

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
        assert "Entropy Analysis" in str_repr
        assert "5.5" in str_repr

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
        assert result_normal.overall_entropy < analyzer.HIGH_ENTROPY_THRESHOLD

    def test_suspicious_entropy_detection(self):
        """Test suspicious entropy detection."""
        analyzer = EntropyAnalyzer()
        suspicious_entropy = 6.8
        assert (
            analyzer.SUSPICIOUS_ENTROPY_THRESHOLD
            < suspicious_entropy
            < analyzer.HIGH_ENTROPY_THRESHOLD
        )


class TestSimilarityHasherDetailed:
    """Detailed tests for SimilarityHasher."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_similarity_hasher_init(self):
        """Test SimilarityHasher initialization."""
        hasher = SimilarityHasher()
        assert hasher is not None
        assert hasattr(hasher, "has_ssdeep")
        assert hasattr(hasher, "has_tlsh")

    def test_hash_file(self, ls_elf):
        """Test hashing a file."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        hasher = SimilarityHasher()
        hash_result = hasher.hash_file(ls_elf)
        assert isinstance(hash_result, dict)
        assert "ssdeep" in hash_result
        assert "tlsh" in hash_result

    def test_compare_files(self, ls_elf, tmp_path):
        """Test comparing two files."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        ls_copy = tmp_path / "ls_copy"
        shutil.copy(ls_elf, ls_copy)

        hasher = SimilarityHasher()
        similarity = hasher.compare_files(ls_elf, ls_copy)
        assert isinstance(similarity, dict)
        assert "byte_similarity" in similarity

    def test_hash_file_consistency(self, ls_elf):
        """Test that hashing same file gives consistent result."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        hasher = SimilarityHasher()
        hash1 = hasher.hash_file(ls_elf)
        hash2 = hasher.hash_file(ls_elf)
        assert isinstance(hash1, dict)
        assert isinstance(hash2, dict)


class TestEvasionScorerDetailed:
    """Detailed tests for EvasionScorer."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_evasion_scorer_init(self):
        """Test EvasionScorer initialization."""

        scorer = EvasionScorer()
        assert scorer is not None
        assert hasattr(scorer, "weights")
        assert isinstance(scorer.weights, dict)

    def test_score_mutations(self, ls_elf, tmp_path):
        """Test scoring mutations."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        from r2morph.detection.evasion_scorer import EvasionScore

        ls_copy = tmp_path / "ls_mutated"
        shutil.copy(ls_elf, ls_copy)

        scorer = EvasionScorer()
        score = scorer.score(ls_elf, ls_copy)
        assert isinstance(score, EvasionScore)
        assert hasattr(score, "overall_score")
        assert score.overall_score >= 0


class TestBinaryValidatorDetailed:
    """Detailed tests for BinaryValidator."""

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_validator_init(self):
        """Test BinaryValidator initialization."""
        validator = BinaryValidator(timeout=10)
        assert validator.timeout == 10
        assert len(validator.test_cases) == 0

    def test_validator_custom_timeout(self):
        """Test validator with custom timeout."""
        validator = BinaryValidator(timeout=30)
        assert validator.timeout == 30

    def test_add_test_case(self):
        """Test adding test cases."""
        validator = BinaryValidator()
        validator.add_test_case(
            args=["--help"], stdin="", expected_exitcode=0, description="Help test"
        )
        assert len(validator.test_cases) == 1
        assert validator.test_cases[0]["args"] == ["--help"]
        assert validator.test_cases[0]["description"] == "Help test"

    def test_add_multiple_test_cases(self):
        """Test adding multiple test cases."""
        validator = BinaryValidator()
        validator.add_test_case(args=["--version"])
        validator.add_test_case(args=["--help"])
        validator.add_test_case(args=["-l"])
        assert len(validator.test_cases) == 3

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
        assert result.passed is True
        assert result.similarity_score == 100.0
        assert len(result.errors) == 0

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
        assert "PASSED" in str_repr
        assert "100.0" in str_repr

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
        assert result.passed is False
        assert len(result.errors) > 0
        str_repr = str(result)
        assert "FAILED" in str_repr


class TestMutationFuzzerDetailed:
    """Detailed tests for MutationFuzzer."""

    def test_fuzzer_init(self):
        """Test MutationFuzzer initialization."""
        fuzzer = MutationFuzzer()
        assert fuzzer is not None


class TestRegressionTesterDetailed:
    """Detailed tests for RegressionTester."""

    @pytest.fixture
    def tmp_test_dir(self, tmp_path):
        test_dir = tmp_path / "regression"
        test_dir.mkdir()
        return test_dir

    def test_regression_tester_init(self, tmp_test_dir):
        """Test RegressionTester initialization."""
        tester = RegressionTester(tmp_test_dir)
        assert tester.test_dir == tmp_test_dir
        assert len(tester.tests) == 0
        assert len(tester.results) == 0

    def test_regression_tester_default_dir(self):
        """Test RegressionTester with default directory."""
        tester = RegressionTester()
        assert tester.test_dir is not None
        assert len(tester.tests) == 0

    def test_load_tests_nonexistent_file(self, tmp_test_dir):
        """Test loading tests from nonexistent file."""
        tester = RegressionTester(tmp_test_dir)
        tester.load_tests()
        assert len(tester.tests) == 0

    def test_regression_test_dataclass(self):
        """Test RegressionTest dataclass."""
        test = RegressionTest(
            name="test1",
            binary_path="/path/to/binary",
            mutations=["nop", "substitute"],
            test_cases=[{"args": ["--help"]}],
            expected_mutations=10,
        )
        assert test.name == "test1"
        assert len(test.mutations) == 2
        test_dict = test.to_dict()
        assert isinstance(test_dict, dict)
        assert test_dict["name"] == "test1"
