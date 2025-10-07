"""
Tests for validation module.
"""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from r2morph.validation.fuzzer import FuzzResult, MutationFuzzer
from r2morph.validation.validator import BinaryValidator, ValidationResult


class TestBinaryValidator:
    """Test cases for BinaryValidator."""

    def test_validator_init(self):
        """Test validator initialization."""
        validator = BinaryValidator(timeout=5)
        assert validator.timeout == 5
        assert len(validator.test_cases) == 0

    def test_add_test_case(self):
        """Test adding test cases."""
        validator = BinaryValidator()
        validator.add_test_case(
            args=["--help"], stdin="", expected_exitcode=0, description="Help test"
        )

        assert len(validator.test_cases) == 1
        assert validator.test_cases[0]["args"] == ["--help"]
        assert validator.test_cases[0]["description"] == "Help test"

    @patch("r2morph.validation.validator.subprocess.run")
    def test_validate_success(self, mock_run):
        """Test successful validation."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = b"output"
        mock_result.stderr = b""
        mock_run.return_value = mock_result

        validator = BinaryValidator()
        validator.add_test_case(description="Test1")

        # Create mock paths that have chmod method
        mock_orig_path = Mock(spec=Path)
        mock_orig_path.name = "original.exe"
        mock_orig_path.chmod.return_value = None

        mock_mut_path = Mock(spec=Path)
        mock_mut_path.name = "mutated.exe"
        mock_mut_path.chmod.return_value = None

        result = validator.validate(mock_orig_path, mock_mut_path)

        assert isinstance(result, ValidationResult)
        assert result.passed is True
        assert result.similarity_score == 100.0

    @patch("r2morph.validation.validator.subprocess.run")
    def test_validate_mismatch(self, mock_run):
        """Test validation with mismatched outputs."""
        mock_result_orig = Mock()
        mock_result_orig.returncode = 0
        mock_result_orig.stdout = b"original output"
        mock_result_orig.stderr = b""

        mock_result_mut = Mock()
        mock_result_mut.returncode = 0
        mock_result_mut.stdout = b"different output"
        mock_result_mut.stderr = b""

        mock_run.side_effect = [mock_result_orig, mock_result_mut]

        validator = BinaryValidator()
        validator.add_test_case(description="Test1")

        result = validator.validate(Path("original.exe"), Path("mutated.exe"))

        assert result.passed is False
        assert len(result.errors) > 0

    @patch("r2morph.validation.validator.subprocess.run")
    def test_validate_timeout(self, mock_run):
        """Test validation with timeout."""
        import subprocess

        # First call (original) succeeds, second call (mutated) times out
        mock_result_orig = Mock()
        mock_result_orig.returncode = 0
        mock_result_orig.stdout = b"output"
        mock_result_orig.stderr = b""

        mock_run.side_effect = [mock_result_orig, subprocess.TimeoutExpired("cmd", 5)]

        validator = BinaryValidator(timeout=1)
        validator.add_test_case(description="Test1")

        # Create mock paths
        mock_orig_path = Mock(spec=Path)
        mock_orig_path.name = "original.exe"
        mock_orig_path.chmod.return_value = None

        mock_mut_path = Mock(spec=Path)
        mock_mut_path.name = "mutated.exe"
        mock_mut_path.chmod.return_value = None

        result = validator.validate(mock_orig_path, mock_mut_path)

        assert result.passed is False
        assert result.mutated_exitcode == -1

    def test_validate_with_inputs(self):
        """Test validation with multiple inputs."""
        validator = BinaryValidator()

        with patch("r2morph.validation.validator.subprocess.run") as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = b"output"
            mock_result.stderr = b""
            mock_run.return_value = mock_result

            result = validator.validate_with_inputs(
                Path("original.exe"), Path("mutated.exe"), ["input1", "input2"]
            )

            assert len(validator.test_cases) == 2
            assert isinstance(result, ValidationResult)


class TestMutationFuzzer:
    """Test cases for MutationFuzzer."""

    def test_fuzzer_init(self):
        """Test fuzzer initialization."""
        fuzzer = MutationFuzzer(num_tests=50, timeout=3)
        assert fuzzer.num_tests == 50
        assert fuzzer.timeout == 3

    def test_generate_random_input(self):
        """Test random input generation."""
        fuzzer = MutationFuzzer(num_tests=10)
        input_str = fuzzer._generate_input("random")
        assert isinstance(input_str, str)

    def test_generate_ascii_input(self):
        """Test ASCII input generation."""
        fuzzer = MutationFuzzer(num_tests=10)
        input_str = fuzzer._generate_input("ascii")
        assert isinstance(input_str, str)

    def test_generate_structured_input(self):
        """Test structured input generation."""
        fuzzer = MutationFuzzer(num_tests=10)
        input_str = fuzzer._generate_input("structured")
        assert isinstance(input_str, str)

    @patch("r2morph.validation.validator.subprocess.run")
    def test_fuzz(self, mock_run):
        """Test fuzzing campaign."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = b"output"
        mock_result.stderr = b""
        mock_run.return_value = mock_result

        fuzzer = MutationFuzzer(num_tests=5, timeout=1)
        result = fuzzer.fuzz(Path("original.exe"), Path("mutated.exe"))

        assert isinstance(result, FuzzResult)
        assert result.total_tests == 5
        assert result.passed + result.failed == 5

    @patch("r2morph.validation.validator.subprocess.run")
    def test_fuzz_with_args(self, mock_run):
        """Test fuzzing with random arguments."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = b"output"
        mock_result.stderr = b""
        mock_run.return_value = mock_result

        fuzzer = MutationFuzzer(num_tests=5, timeout=1)
        result = fuzzer.fuzz_with_args(Path("original.exe"), Path("mutated.exe"))

        assert isinstance(result, FuzzResult)
        assert result.total_tests == 5

    def test_fuzz_result_success_rate(self):
        """Test fuzz result success rate calculation."""
        result = FuzzResult(
            total_tests=100,
            passed=90,
            failed=10,
            crashes=2,
            timeouts=1,
            validation_results=[],
        )

        assert result.success_rate == 90.0
        assert "90.0%" in str(result)
