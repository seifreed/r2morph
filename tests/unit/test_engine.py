"""
Unit tests for MorphEngine (real binaries required).
"""

import importlib.util
from pathlib import Path

import pytest

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


from r2morph import MorphEngine
from r2morph.mutations import NopInsertionPass


class TestMorphEngine:
    """Tests for the MorphEngine class."""

    def test_engine_load_and_analyze(self, tmp_path):
        test_file = Path(__file__).parent.parent / "fixtures" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        output = tmp_path / "simple_engine"
        output.write_bytes(test_file.read_bytes())

        with MorphEngine() as engine:
            engine.load_binary(output)
            engine.analyze(level="aa")
            stats = engine.get_stats()

        assert isinstance(stats, dict)
        assert "functions" in stats

    def test_engine_run_and_save(self, tmp_path):
        test_file = Path(__file__).parent.parent / "fixtures" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        output = tmp_path / "simple_engine_run"
        output.write_bytes(test_file.read_bytes())

        with MorphEngine() as engine:
            engine.load_binary(output)
            engine.add_mutation(NopInsertionPass(config={"probability": 0.2}))
            result = engine.run()
            saved = tmp_path / "simple_engine_saved"
            engine.save(saved)

        assert isinstance(result, dict)
        assert saved.exists()
