"""
Unit tests for Pipeline (real binaries required).
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
from r2morph.mutations import NopInsertionPass, RegisterSubstitutionPass
from r2morph.pipeline import Pipeline

_EXPECTED_LEN_PIPELINE_2 = 2


class TestPipeline:
    """Tests for the Pipeline class."""

    def test_add_and_remove_pass(self):
        """Test adding and removing passes."""
        pipeline = Pipeline()
        nop_pass = NopInsertionPass()
        reg_pass = RegisterSubstitutionPass()

        pipeline.add_pass(nop_pass)
        pipeline.add_pass(reg_pass)

        expect(len(pipeline) == _EXPECTED_LEN_PIPELINE_2)
        expect(not ("NopInsertion" not in pipeline.get_pass_names()))

        removed = pipeline.remove_pass("NopInsertion")
        expect(not (removed is not True))
        expect("NopInsertion" not in pipeline.get_pass_names())

    def test_pipeline_run(self, tmp_path):
        """Test running pipeline on a real binary."""
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        temp_binary = tmp_path / "simple_pipeline"
        temp_binary.write_bytes(test_file.read_bytes())

        pipeline = Pipeline()
        pipeline.add_pass(NopInsertionPass(config={"probability": 0.2}))
        pipeline.add_pass(RegisterSubstitutionPass(config={"probability": 0.2}))

        with Binary(temp_binary, writable=True) as binary:
            binary.analyze()
            result = pipeline.run(binary)

        expect(isinstance(result, dict))
        expect(not ("passes_run" not in result))
        expect(not ("total_mutations" not in result))
