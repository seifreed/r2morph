"""
Unit tests for Binary class (real r2pipe required).
"""

import importlib.util
from pathlib import Path

import pytest

from tests.utils.assertions import expect

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


from r2morph.core.binary import Binary


class TestBinary:
    """Tests for the Binary class."""

    def test_binary_init_with_nonexistent_file(self):
        """Test that initializing with non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            Binary("/path/to/nonexistent/binary")

    def test_binary_context_manager(self):
        """Test using Binary as a context manager."""
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        with Binary(test_file) as binary:
            expect(binary.r2 is not None)

    def test_binary_analyze(self):
        """Test binary analysis."""
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        with Binary(test_file) as binary:
            binary.analyze()
            expect(binary.is_analyzed())

    def test_get_functions(self):
        """Test getting functions from binary."""
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        with Binary(test_file) as binary:
            binary.analyze()
            functions = binary.get_functions()
            expect(isinstance(functions, list))
            expect(not (len(functions) < 0))

    def test_get_arch_info(self):
        """Test getting architecture information."""
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        with Binary(test_file) as binary:
            binary.analyze()
            arch_info = binary.get_arch_info()
            expect(not ("arch" not in arch_info))
            expect(not ("bits" not in arch_info))
