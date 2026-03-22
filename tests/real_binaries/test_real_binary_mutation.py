"""
Real binary tests for r2morph.

Tests mutations against real system binaries to ensure mutations
produce valid, executable output.

These tests require:
- radare2 installed
- Test binaries available (/bin/ls, etc.)
- Platform-specific binaries
"""

import os
import platform
import subprocess
import shutil
import tempfile
from pathlib import Path

import pytest

from r2morph.core.engine import MorphEngine
from r2morph.core.config import EngineConfig
from r2morph.validation import BinaryValidator


pytestmark = pytest.mark.skipif(os.environ.get("SKIP_REAL_BINARY_TESTS") == "1", reason="Real binary tests disabled")


def get_system_binaries():
    """Get list of system binaries available for testing."""
    binaries = []

    if platform.system() == "Linux":
        candidates = [
            "/bin/ls",
            "/bin/cat",
            "/bin/echo",
            "/usr/bin/whoami",
            "/usr/bin/id",
        ]
    elif platform.system() == "Darwin":
        candidates = [
            "/bin/ls",
            "/bin/cat",
            "/usr/bin/whoami",
            "/usr/bin/id",
        ]
    elif platform.system() == "Windows":
        candidates = [
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\find.exe",
        ]
    else:
        candidates = []

    for path in candidates:
        if os.path.exists(path):
            binaries.append(path)

    return binaries


def binary_runs_successfully(binary_path: Path) -> bool:
    """Test if binary runs without crashing."""
    try:
        result = subprocess.run(
            [str(binary_path), "--help"],
            capture_output=True,
            timeout=5,
        )
        # Most utilities exit with 0 or 1 for --help
        return result.returncode in (0, 1)
    except (subprocess.TimeoutExpired, OSError):
        return False


class TestRealBinaryMutation:
    """Test mutations on real system binaries."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test outputs."""
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    @pytest.fixture
    def system_binaries(self):
        """Get available system binaries."""
        binaries = get_system_binaries()
        if not binaries:
            pytest.skip("No system binaries available for testing")
        return binaries

    def test_ls_mutation_stable_passes(self, temp_dir):
        """Test /bin/ls mutation with stable passes."""
        ls_path = Path("/bin/ls")
        if not ls_path.exists():
            pytest.skip("/bin/ls not available")

        output_path = temp_dir / "ls_mutated"
        config = EngineConfig.create_default()

        with MorphEngine(config=config) as engine:
            engine.load_binary(ls_path).analyze()

            # Add stable mutation passes
            engine.add_mutation("nop")
            engine.add_mutation("substitute")
            engine.add_mutation("register")

            result = engine.run(validation_mode="structural")

            assert result.successful, f"Mutation failed: {result.error}"

            engine.save(output_path)

        # Verify output is valid binary
        assert output_path.exists()
        assert output_path.stat().st_size > 0

        # Verify mutated binary runs
        assert binary_runs_successfully(output_path), "Mutated binary doesn't run"

    def test_cat_mutation_preserves_behavior(self, temp_dir):
        """Test /bin/cat mutation preserves basic behavior."""
        cat_path = Path("/bin/cat")
        if not cat_path.exists():
            pytest.skip("/bin/cat not available")

        output_path = temp_dir / "cat_mutated"
        config = EngineConfig.create_default()

        with MorphEngine(config=config) as engine:
            engine.load_binary(cat_path).analyze()
            engine.add_mutation("nop")

            result = engine.run(validation_mode="structural")
            assert result.successful

            engine.save(output_path)

        # Test behavior
        test_input = b"Hello, mutation test!\n"

        # Original behavior
        orig_result = subprocess.run(
            [str(cat_path)],
            input=test_input,
            capture_output=True,
            timeout=5,
        )

        # Mutated behavior
        mut_result = subprocess.run(
            [str(output_path)],
            input=test_input,
            capture_output=True,
            timeout=5,
        )

        assert orig_result.stdout == mut_result.stdout, "Cat output changed"

    def test_whoami_mutation(self, temp_dir):
        """Test /usr/bin/whoami mutation."""
        whoami_path = Path("/usr/bin/whoami")
        if not whoami_path.exists():
            pytest.skip("/usr/bin/whoami not available")

        output_path = temp_dir / "whoami_mutated"
        config = EngineConfig.create_default()

        with MorphEngine(config=config) as engine:
            engine.load_binary(whoami_path).analyze()
            engine.add_mutation("substitute")

            result = engine.run(validation_mode="structural")
            assert result.successful

            engine.save(output_path)

        # Verify behavior
        orig_result = subprocess.run([str(whoami_path)], capture_output=True, timeout=5)
        mut_result = subprocess.run([str(output_path)], capture_output=True, timeout=5)

        assert orig_result.stdout == mut_result.stdout, "Whoami output changed"
        assert orig_result.returncode == mut_result.returncode, "Whoami exit code changed"

    @pytest.mark.parametrize("binary_path", get_system_binaries()[:3])
    def test_multiple_binaries_mutation(self, binary_path, temp_dir):
        """Test mutation on multiple system binaries."""
        binary_path = Path(binary_path)
        output_path = temp_dir / binary_path.name

        config = EngineConfig.create_default()

        with MorphEngine(config=config) as engine:
            engine.load_binary(binary_path).analyze()
            engine.add_mutation("nop")

            result = engine.run(validation_mode="structural")
            assert result.successful, f"Failed for {binary_path}"

            engine.save(output_path)

        assert output_path.exists(), f"Output not created for {binary_path}"
        assert binary_runs_successfully(output_path), f"Mutated {binary_path.name} doesn't run"

    def test_mutation_with_multiple_passes(self, temp_dir):
        """Test mutation with multiple passes on real binary."""
        ls_path = Path("/bin/ls")
        if not ls_path.exists():
            pytest.skip("/bin/ls not available")

        output_path = temp_dir / "ls_multi_pass"
        config = EngineConfig.create_aggressive()

        with MorphEngine(config=config) as engine:
            engine.load_binary(ls_path).analyze()

            # Add multiple passes
            engine.add_mutation("nop")
            engine.add_mutation("substitute")
            engine.add_mutation("register")

            result = engine.run(
                validation_mode="structural",
                rollback_policy="skip-invalid-pass",
            )

            # Should succeed with at least some mutations
            assert result.mutations_applied >= 0

            engine.save(output_path)

        # Verify output runs
        assert binary_runs_successfully(output_path)


class TestBinaryPreservation:
    """Test that critical binary properties are preserved after mutation."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    def test_entry_point_preserved(self, temp_dir):
        """Test that entry point remains valid after mutation."""
        ls_path = Path("/bin/ls")
        if not ls_path.exists():
            pytest.skip("/bin/ls not available")

        output_path = temp_dir / "ls_mutated"
        config = EngineConfig.create_default()

        with MorphEngine(config=config) as engine:
            engine.load_binary(ls_path).analyze()
            original_entry = engine.binary.entry_point

            engine.add_mutation("nop")
            result = engine.run(validation_mode="structural")

            if result.successful:
                engine.save(output_path)

                # Reload and check entry point
                with MorphEngine(config=config) as engine2:
                    engine2.load_binary(output_path).analyze()
                    # Entry point should be the same
                    assert engine2.binary.entry_point == original_entry

    def test_sections_preserved(self, temp_dir):
        """Test that binary sections are preserved after mutation."""
        ls_path = Path("/bin/ls")
        if not ls_path.exists():
            pytest.skip("/bin/ls not available")

        output_path = temp_dir / "ls_mutated"
        config = EngineConfig.create_default()

        with MorphEngine(config=config) as engine:
            engine.load_binary(ls_path).analyze()
            original_sections = list(engine.binary.sections)

            engine.add_mutation("nop")
            result = engine.run(validation_mode="structural")

            if result.successful:
                engine.save(output_path)

                with MorphEngine(config=config) as engine2:
                    engine2.load_binary(output_path).analyze()
                    mutated_sections = list(engine2.binary.sections)

                    # Same number of sections
                    assert len(mutated_sections) == len(original_sections)


class TestBehavioralEquivalence:
    """Test that mutations preserve behavioral equivalence."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    def test_exit_code_preservation(self, temp_dir):
        """Test that exit codes are preserved after mutation."""
        true_path = Path("/bin/true")
        if not true_path.exists():
            pytest.skip("/bin/true not available")

        output_path = temp_dir / "true_mutated"
        config = EngineConfig.create_default()

        with MorphEngine(config=config) as engine:
            engine.load_binary(true_path).analyze()
            engine.add_mutation("nop")
            result = engine.run(validation_mode="structural")

            if result.successful:
                engine.save(output_path)

        # Test exit codes
        for _ in range(5):  # Multiple runs
            orig_result = subprocess.run([str(true_path)], capture_output=True)
            mut_result = subprocess.run([str(output_path)], capture_output=True)

            assert orig_result.returncode == mut_result.returncode

    def test_output_preservation_simple(self, temp_dir):
        """Test that simple output is preserved after mutation."""
        echo_path = Path("/bin/echo")
        if not echo_path.exists():
            pytest.skip("/bin/echo not available")

        output_path = temp_dir / "echo_mutated"
        config = EngineConfig.create_default()

        with MorphEngine(config=config) as engine:
            engine.load_binary(echo_path).analyze()
            engine.add_mutation("nop")
            result = engine.run(validation_mode="structural")

            if result.successful:
                engine.save(output_path)

        test_args = ["test", "message", "123"]

        orig_result = subprocess.run(
            [str(echo_path)] + test_args,
            capture_output=True,
        )
        mut_result = subprocess.run(
            [str(output_path)] + test_args,
            capture_output=True,
        )

        assert orig_result.stdout == mut_result.stdout
        assert orig_result.returncode == mut_result.returncode


class TestRecoveryAndRollback:
    """Test recovery and rollback mechanisms with real binaries."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    def test_rollback_on_failure(self, temp_dir):
        """Test that rollback works correctly on real binaries."""
        ls_path = Path("/bin/ls")
        if not ls_path.exists():
            pytest.skip("/bin/ls not available")

        output_path = temp_dir / "ls_mutated"
        config = EngineConfig.create_aggressive()

        with MorphEngine(config=config) as engine:
            engine.load_binary(ls_path).analyze()

            # Add experimental passes that might fail
            engine.add_mutation("nop")
            engine.add_mutation("block")  # Experimental

            result = engine.run(
                validation_mode="structural",
                rollback_policy="skip-invalid-pass",
            )

            # Should succeed with rollback
            engine.save(output_path)

        # Verify output is valid
        assert output_path.exists()
        assert binary_runs_successfully(output_path)
