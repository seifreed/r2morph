"""
Unit tests for Pipeline class.
"""

from unittest.mock import Mock

from r2morph.mutations.base import MutationPass
from r2morph.pipeline.pipeline import Pipeline


class MockMutation(MutationPass):
    """Mock mutation pass for testing."""

    def __init__(self, name="MockMutation"):
        super().__init__(name=name)

    def apply(self, binary):
        return {"mutations_applied": 5}


class TestPipeline:
    """Tests for the Pipeline class."""

    def test_pipeline_init(self):
        """Test pipeline initialization."""
        pipeline = Pipeline()
        assert len(pipeline) == 0
        assert pipeline.get_pass_names() == []

    def test_add_pass(self):
        """Test adding a pass to pipeline."""
        pipeline = Pipeline()
        mutation = MockMutation()

        pipeline.add_pass(mutation)
        assert len(pipeline) == 1
        assert "MockMutation" in pipeline.get_pass_names()

    def test_remove_pass(self):
        """Test removing a pass from pipeline."""
        pipeline = Pipeline()
        mutation = MockMutation()

        pipeline.add_pass(mutation)
        assert len(pipeline) == 1

        result = pipeline.remove_pass("MockMutation")
        assert result is True
        assert len(pipeline) == 0

        result = pipeline.remove_pass("NonExistent")
        assert result is False

    def test_clear(self):
        """Test clearing pipeline."""
        pipeline = Pipeline()
        pipeline.add_pass(MockMutation("Pass1"))
        pipeline.add_pass(MockMutation("Pass2"))

        assert len(pipeline) == 2

        pipeline.clear()
        assert len(pipeline) == 0

    def test_run_empty_pipeline(self):
        """Test running an empty pipeline."""
        pipeline = Pipeline()
        mock_binary = Mock()

        result = pipeline.run(mock_binary)
        assert result["passes_run"] == 0
        assert result["total_mutations"] == 0

    def test_run_with_passes(self):
        """Test running pipeline with passes."""
        pipeline = Pipeline()
        pipeline.add_pass(MockMutation("Pass1"))
        pipeline.add_pass(MockMutation("Pass2"))

        mock_binary = Mock()

        result = pipeline.run(mock_binary)
        assert result["passes_run"] == 2
        assert result["total_mutations"] == 10
        assert "Pass1" in result["pass_results"]
        assert "Pass2" in result["pass_results"]

    def test_run_with_failing_pass(self):
        """Test running pipeline when a pass fails."""

        class FailingMutation(MutationPass):
            def __init__(self):
                super().__init__(name="FailingMutation")

            def apply(self, binary):
                raise ValueError("Test error")

        pipeline = Pipeline()
        pipeline.add_pass(MockMutation("Pass1"))
        pipeline.add_pass(FailingMutation())
        pipeline.add_pass(MockMutation("Pass2"))

        mock_binary = Mock()

        result = pipeline.run(mock_binary)

        assert result["pass_results"]["Pass1"]["mutations_applied"] == 5

        assert "error" in result["pass_results"]["FailingMutation"]

        assert result["pass_results"]["Pass2"]["mutations_applied"] == 5
