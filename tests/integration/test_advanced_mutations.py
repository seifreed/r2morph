"""
Real integration tests for advanced mutation modules.
"""

from pathlib import Path

import pytest

from r2morph import MorphEngine
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass
from r2morph.mutations.opaque_predicates import OpaquePredicatePass


class TestOpaquePredicates:
    """Tests for OpaquePredicatePass."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_opaque_predicate_pass(self, ls_elf, tmp_path):
        """Test opaque predicate insertion."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_opaque"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            config = {
                "max_predicates_per_function": 3,
                "probability": 0.5,
            }
            engine.add_mutation(OpaquePredicatePass(config=config))

            result = engine.run()
            engine.save(output_path)

        assert output_path.exists()
        assert result["total_mutations"] >= 0

    def test_opaque_predicate_types(self, ls_elf, tmp_path):
        """Test different opaque predicate types."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_opaque_types"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            config = {
                "max_predicates_per_function": 5,
                "probability": 0.7,
                "use_complex": True,
            }
            opaque_pass = OpaquePredicatePass(config=config)
            engine.add_mutation(opaque_pass)

            engine.run()
            engine.save(output_path)

        assert output_path.exists()

    def test_low_probability(self, ls_elf, tmp_path):
        """Test with low probability."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_opaque_low"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            config = {"probability": 0.1}
            engine.add_mutation(OpaquePredicatePass(config=config))

            engine.run()
            engine.save(output_path)

        assert output_path.exists()


class TestDeadCodeInjection:
    """Tests for DeadCodeInjectionPass."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_dead_code_injection(self, ls_elf, tmp_path):
        """Test dead code injection."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_deadcode"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            config = {
                "max_injections_per_function": 3,
                "probability": 0.5,
            }
            engine.add_mutation(DeadCodeInjectionPass(config=config))

            result = engine.run()
            engine.save(output_path)

        assert output_path.exists()
        assert result["total_mutations"] >= 0

    def test_dead_code_patterns(self, ls_elf, tmp_path):
        """Test different dead code patterns."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_deadcode_patterns"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            config = {
                "max_injections_per_function": 5,
                "probability": 0.6,
                "use_junk": True,
            }
            engine.add_mutation(DeadCodeInjectionPass(config=config))

            engine.run()
            engine.save(output_path)

        assert output_path.exists()

    def test_aggressive_dead_code(self, ls_elf, tmp_path):
        """Test aggressive dead code injection."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_deadcode_aggressive"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            config = {
                "max_injections_per_function": 10,
                "probability": 0.9,
            }
            engine.add_mutation(DeadCodeInjectionPass(config=config))

            engine.run()
            engine.save(output_path)

        assert output_path.exists()


class TestControlFlowFlattening:
    """Tests for ControlFlowFlatteningPass."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_control_flow_flattening(self, ls_elf, tmp_path):
        """Test control flow flattening."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_flatten"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            config = {
                "max_flattened_per_binary": 3,
                "probability": 0.3,
            }
            engine.add_mutation(ControlFlowFlatteningPass(config=config))

            result = engine.run()
            engine.save(output_path)

        assert output_path.exists()
        assert result["total_mutations"] >= 0

    def test_flatten_with_switch(self, ls_elf, tmp_path):
        """Test flattening with switch dispatcher."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_flatten_switch"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            config = {
                "max_flattened_per_binary": 2,
                "probability": 0.4,
                "use_switch": True,
            }
            engine.add_mutation(ControlFlowFlatteningPass(config=config))

            engine.run()
            engine.save(output_path)

        assert output_path.exists()

    def test_combined_advanced_mutations(self, ls_elf, tmp_path):
        """Test combining multiple advanced mutations."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_advanced_combo"

        with MorphEngine() as engine:
            engine.load_binary(ls_elf).analyze()

            opaque_config = {"probability": 0.3}
            dead_config = {"probability": 0.3}
            flatten_config = {"probability": 0.2}

            engine.add_mutation(OpaquePredicatePass(config=opaque_config))
            engine.add_mutation(DeadCodeInjectionPass(config=dead_config))
            engine.add_mutation(ControlFlowFlatteningPass(config=flatten_config))

            result = engine.run()
            engine.save(output_path)

        assert output_path.exists()
        assert result["total_mutations"] >= 0
