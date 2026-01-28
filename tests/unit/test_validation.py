"""
Unit tests for validation utilities using real binaries.
"""

import importlib.util
from pathlib import Path

import pytest

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)

from r2morph.validation.validator import BinaryValidator


class TestBinaryValidator:
    """Tests for BinaryValidator with real binaries."""

    @pytest.fixture
    def simple_binary(self):
        return Path(__file__).parent.parent / "fixtures" / "simple"

    def test_validator_default_case(self, simple_binary, tmp_path):
        if not simple_binary.exists():
            pytest.skip("Test binary not available")

        temp_copy = tmp_path / "simple_copy"
        temp_copy.write_bytes(simple_binary.read_bytes())

        validator = BinaryValidator(timeout=5)
        result = validator.validate(simple_binary, temp_copy)

        assert result is not None
        assert hasattr(result, "passed")

    def test_validator_with_args(self, simple_binary, tmp_path):
        if not simple_binary.exists():
            pytest.skip("Test binary not available")

        temp_copy = tmp_path / "simple_copy_args"
        temp_copy.write_bytes(simple_binary.read_bytes())

        validator = BinaryValidator(timeout=5)
        validator.add_test_case(args=["--help"], description="help")
        result = validator.validate(simple_binary, temp_copy)

        assert result is not None
        assert hasattr(result, "similarity_score")
