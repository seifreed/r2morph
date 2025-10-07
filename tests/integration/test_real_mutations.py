"""
Real integration tests for mutations using compiled binaries.
"""

import platform
import subprocess
from pathlib import Path

import pytest

from r2morph import MorphEngine
from r2morph.mutations import (
    InstructionSubstitutionPass,
    NopInsertionPass,
    RegisterSubstitutionPass,
)


class TestRealMutations:
    """Integration tests with real binaries."""

    @pytest.fixture
    def simple_binary(self):
        """Path to simple test binary."""
        return Path(__file__).parent.parent / "fixtures" / "simple"

    @pytest.fixture
    def loop_binary(self):
        """Path to loop test binary."""
        return Path(__file__).parent.parent / "fixtures" / "loop"

    @pytest.fixture
    def conditional_binary(self):
        """Path to conditional test binary."""
        return Path(__file__).parent.parent / "fixtures" / "conditional"

    def check_platform(self):
        """Skip tests on macOS due to ARM64 binary complexity."""
        if platform.system() == "Darwin":
            pytest.skip("Real mutation tests skipped on macOS (ARM64 binary complexity)")

    def get_output(self, binary_path):
        """Get output from executing a binary."""
        try:
            result = subprocess.run(
                [str(binary_path)],
                capture_output=True,
                timeout=5,
                check=False,
            )
            return result.stdout.decode(), result.returncode
        except Exception as e:
            return f"Error: {e}", -1

    def test_nop_insertion_real(self, simple_binary, tmp_path):
        """Test NOP insertion with real binary."""
        self.check_platform()

        if not simple_binary.exists():
            pytest.skip("Test binary not available")

        output_path = tmp_path / "simple_nop"

        with MorphEngine() as engine:
            engine.load_binary(simple_binary).analyze()

            config = {
                "max_nops_per_function": 5,
                "probability": 0.8,
                "use_creative_nops": True,
            }
            engine.add_mutation(NopInsertionPass(config=config))

            result = engine.run()
            engine.save(output_path)

        assert output_path.exists()
        assert result["total_mutations"] >= 0

        orig_output, orig_code = self.get_output(simple_binary)
        mut_output, mut_code = self.get_output(output_path)

        assert orig_code == mut_code
        assert orig_output == mut_output

    def test_instruction_substitution_real(self, loop_binary, tmp_path):
        """Test instruction substitution with real binary."""
        self.check_platform()

        if not loop_binary.exists():
            pytest.skip("Test binary not available")

        output_path = tmp_path / "loop_subst"

        with MorphEngine() as engine:
            engine.load_binary(loop_binary).analyze()

            config = {
                "max_substitutions_per_function": 10,
                "probability": 0.7,
                "strict_size": True,
            }
            engine.add_mutation(InstructionSubstitutionPass(config=config))

            engine.run()
            engine.save(output_path)

        assert output_path.exists()

        orig_output, orig_code = self.get_output(loop_binary)
        mut_output, mut_code = self.get_output(output_path)

        assert orig_code == mut_code
        assert orig_output == mut_output

    def test_multiple_mutations_real(self, conditional_binary, tmp_path):
        """Test multiple mutations on real binary."""
        self.check_platform()

        if not conditional_binary.exists():
            pytest.skip("Test binary not available")

        output_path = tmp_path / "conditional_multi"

        with MorphEngine() as engine:
            engine.load_binary(conditional_binary).analyze()

            nop_config = {"max_nops_per_function": 3, "probability": 0.6}
            subst_config = {"max_substitutions_per_function": 5, "probability": 0.5}
            reg_config = {"max_substitutions_per_function": 3, "probability": 0.4}

            engine.add_mutation(NopInsertionPass(config=nop_config))
            engine.add_mutation(InstructionSubstitutionPass(config=subst_config))
            engine.add_mutation(RegisterSubstitutionPass(config=reg_config))

            result = engine.run()
            engine.save(output_path)

        assert output_path.exists()
        assert result["total_mutations"] >= 0

        orig_output, orig_code = self.get_output(conditional_binary)
        mut_output, mut_code = self.get_output(output_path)

        assert orig_code == mut_code
        assert orig_output == mut_output

    def test_aggressive_mode_real(self, simple_binary, tmp_path):
        """Test aggressive mode with real binary."""
        self.check_platform()

        if not simple_binary.exists():
            pytest.skip("Test binary not available")

        output_path = tmp_path / "simple_aggressive"

        with MorphEngine() as engine:
            engine.load_binary(simple_binary).analyze()

            nop_config = {
                "max_nops_per_function": 15,
                "probability": 0.9,
                "use_creative_nops": True,
            }
            subst_config = {
                "max_substitutions_per_function": 20,
                "probability": 0.9,
            }

            engine.add_mutation(NopInsertionPass(config=nop_config))
            engine.add_mutation(InstructionSubstitutionPass(config=subst_config))

            result = engine.run()
            engine.save(output_path)

        assert output_path.exists()
        assert result["total_mutations"] > 0

        orig_output, orig_code = self.get_output(simple_binary)
        mut_output, mut_code = self.get_output(output_path)

        assert orig_code == mut_code
        assert orig_output == mut_output

    def test_binary_still_executable(self, loop_binary, tmp_path):
        """Test that mutated binary is still executable."""
        self.check_platform()

        if not loop_binary.exists():
            pytest.skip("Test binary not available")

        output_path = tmp_path / "loop_exec_test"

        with MorphEngine() as engine:
            engine.load_binary(loop_binary).analyze()
            engine.add_mutation(NopInsertionPass())
            engine.run()
            engine.save(output_path)

        assert output_path.exists()

        output_path.chmod(0o755)

        result = subprocess.run([str(output_path)], capture_output=True, timeout=5, check=False)

        assert result.returncode == 0
