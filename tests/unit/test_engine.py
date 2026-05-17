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
from r2morph.mutations import InstructionSubstitutionPass, NopInsertionPass
from tests._doubles.recording_binary_signer import RecordingBinarySigner


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

    def test_remove_mutation_drops_all_matching_and_chains(self):
        engine = MorphEngine()
        engine.add_mutation(NopInsertionPass(config={"probability": 0.0}))
        engine.add_mutation(NopInsertionPass(config={"probability": 0.0}))
        engine.add_mutation(InstructionSubstitutionPass(config={"probability": 0.0}))

        names_before = [pass_.name for pass_ in engine.mutations]
        assert names_before.count("NopInsertion") == 2

        returned = engine.remove_mutation("NopInsertion")

        assert returned is engine
        names_after = [pass_.name for pass_ in engine.mutations]
        assert "NopInsertion" not in names_after
        assert names_after == ["InstructionSubstitution"]

    def test_save_delegates_to_injected_binary_signer(self, tmp_path):
        test_file = Path(__file__).parent.parent / "fixtures" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        source = tmp_path / "simple_signer_src"
        source.write_bytes(test_file.read_bytes())
        output = tmp_path / "simple_signer_out"
        recorder = RecordingBinarySigner()

        with MorphEngine(binary_signer=recorder) as engine:
            engine.load_binary(source)
            engine.save(output)

            assert output.exists()
            assert len(recorder.calls) == 1
            signed_path, used_config = recorder.calls[0]
            assert signed_path == output
            assert used_config is engine.config

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
