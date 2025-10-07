"""
Tests for MorphEngine.
"""

from unittest.mock import MagicMock, Mock, patch

import pytest

from r2morph.core.engine import MorphEngine
from r2morph.mutations.base import MutationPass


class TestMorphEngine:
    """Test cases for MorphEngine class."""

    def test_engine_init(self):
        """Test engine initialization."""
        engine = MorphEngine()
        assert engine.binary is None
        assert len(engine.mutations) == 0
        assert engine.pipeline is not None

    def test_engine_context_manager(self):
        """Test engine as context manager."""
        with MorphEngine() as engine:
            assert engine is not None

    @patch("r2morph.core.engine.Binary")
    def test_load_binary(self, mock_binary_class):
        """Test loading a binary."""
        mock_binary = Mock()
        mock_binary_class.return_value = mock_binary

        engine = MorphEngine()
        result = engine.load_binary("test.exe")

        assert result == engine
        assert engine.binary == mock_binary
        mock_binary_class.assert_called_once()

    def test_add_mutation(self):
        """Test adding a mutation pass."""
        engine = MorphEngine()
        mock_mutation = Mock(spec=MutationPass)
        mock_mutation.name = "TestMutation"

        engine.add_mutation(mock_mutation)

        assert len(engine.mutations) == 1
        assert mock_mutation in engine.mutations

    def test_remove_mutation(self):
        """Test removing a mutation pass."""
        engine = MorphEngine()
        mock_mutation = Mock(spec=MutationPass)
        mock_mutation.name = "TestMutation"

        engine.add_mutation(mock_mutation)
        engine.remove_mutation("TestMutation")

        assert len(engine.mutations) == 0

    @patch("r2morph.core.engine.Binary")
    def test_analyze(self, mock_binary_class):
        """Test analyzing a binary."""
        mock_binary = Mock()
        mock_binary.analyze.return_value = mock_binary
        mock_binary_class.return_value = mock_binary

        engine = MorphEngine()
        engine.load_binary("test.exe")
        result = engine.analyze()

        assert result == engine
        mock_binary.analyze.assert_called_once()

    @patch("r2morph.core.engine.Binary")
    def test_run_with_mutations(self, mock_binary_class):
        """Test running mutations."""
        mock_binary = Mock()
        mock_binary_class.return_value = mock_binary

        mock_mutation = Mock(spec=MutationPass)
        mock_mutation.name = "TestMutation"
        mock_mutation.apply.return_value = {"mutations_applied": 5}

        engine = MorphEngine()
        engine.load_binary("test.exe")
        engine.add_mutation(mock_mutation)

        result = engine.run()

        assert result is not None
        assert result["total_mutations"] >= 0
        mock_mutation.apply.assert_called_once_with(mock_binary)

    @patch("r2morph.core.engine.Binary")
    def test_save(self, mock_binary_class):
        """Test saving morphed binary."""
        mock_binary = Mock()
        mock_binary_class.return_value = mock_binary

        engine = MorphEngine()
        engine.load_binary("test.exe")
        engine.save("output.exe")

        mock_binary.save.assert_called_once_with("output.exe")

    def test_run_without_binary(self):
        """Test running without loading a binary."""
        engine = MorphEngine()

        with pytest.raises(RuntimeError):
            engine.run()

    def test_save_without_binary(self):
        """Test saving without loading a binary."""
        engine = MorphEngine()

        with pytest.raises(RuntimeError):
            engine.save("output.exe")
