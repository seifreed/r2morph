"""
Unit tests for MorphEngine (real binaries required).
"""

import importlib.util
from pathlib import Path

import pytest

from tests.utils.assertions import expect

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


from r2morph import MorphEngine
from r2morph.mutations import InstructionSubstitutionPass, NopInsertionPass
from tests._doubles.recording_binary_signer import RecordingBinarySigner

_EXPECTED_NAMES_BEFORE_COUNT_NOPINSERTION_2 = 2


class TestMorphEngine:
    """Tests for the MorphEngine class."""

    def test_engine_load_and_analyze(self, tmp_path):
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        output = tmp_path / "simple_engine"
        output.write_bytes(test_file.read_bytes())

        with MorphEngine() as engine:
            engine.load_binary(output)
            engine.analyze(level="aa")
            stats = engine.get_stats()

        expect(isinstance(stats, dict))
        expect(not ("functions" not in stats))

    def test_remove_mutation_drops_all_matching_and_chains(self):
        engine = MorphEngine()
        engine.add_mutation(NopInsertionPass(config={"probability": 0.0}))
        engine.add_mutation(NopInsertionPass(config={"probability": 0.0}))
        engine.add_mutation(InstructionSubstitutionPass(config={"probability": 0.0}))

        names_before = [pass_.name for pass_ in engine.mutations]
        expect(names_before.count("NopInsertion") == _EXPECTED_NAMES_BEFORE_COUNT_NOPINSERTION_2)

        returned = engine.remove_mutation("NopInsertion")

        expect(not (returned is not engine))
        names_after = [pass_.name for pass_ in engine.mutations]
        expect("NopInsertion" not in names_after)
        expect(names_after == ["InstructionSubstitution"])

    def test_save_delegates_to_injected_binary_signer(self, tmp_path):
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
        if not test_file.exists():
            pytest.skip("Test binary not available")

        source = tmp_path / "simple_signer_src"
        source.write_bytes(test_file.read_bytes())
        output = tmp_path / "simple_signer_out"
        recorder = RecordingBinarySigner()

        with MorphEngine(binary_signer=recorder) as engine:
            engine.load_binary(source)
            engine.save(output)

            expect(output.exists())
            expect(len(recorder.calls) == 1)
            signed_path, used_config = recorder.calls[0]
            expect(signed_path == output)
            expect(not (used_config is not engine.config))

    def test_engine_run_and_save(self, tmp_path):
        test_file = Path(__file__).parents[2] / "fixtures" / "synthetic" / "simple"
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

        expect(isinstance(result, dict))
        expect(saved.exists())
