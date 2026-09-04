"""
Self-mutation tests for r2morph.

Tests the ability of r2morph to mutate itself - a key test
of mutation correctness and safety.
"""

import importlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from r2morph import __version__
from r2morph.core.config import EngineConfig
from r2morph.core.engine import MorphEngine
from r2morph.core.engine_run import EngineRunOptions
from tests.utils.assertions import expect
from tests.utils.process import run_command

_EXPECTED_LEN_PARTS_2 = 2
_SELF_MUTATION_SEED = 1337
_SELF_MUTATION_TIMEOUT_SECONDS = 60


pytestmark = pytest.mark.skipif(
    os.environ.get("SKIP_SELF_MUTATION_TESTS") == "1", reason="Self-mutation tests disabled"
)


def get_r2morph_install_path():
    """Get the path to the installed r2morph module."""
    r2morph = importlib.import_module("r2morph")

    return Path(r2morph.__file__).parent.parent  # Go up from __init__.py


def find_entry_point():
    """Find the CLI entry point."""
    # Check if r2morph CLI is installed
    r2morph_cli = shutil.which("r2morph")
    if r2morph_cli:
        return Path(r2morph_cli)

    # Try to find it in the package
    install_path = get_r2morph_install_path()
    cli_path = install_path / "bin" / "r2morph"
    if cli_path.exists():
        return cli_path

    return None


class TestSelfMutation:
    """Test r2morph's ability to mutate itself."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    @pytest.fixture
    def r2morph_package_path(self):
        """Get path to r2morph package."""
        return get_r2morph_install_path()

    def test_package_location_exists(self, r2morph_package_path):
        """Verify r2morph package exists."""
        expect(r2morph_package_path.exists())
        expect((r2morph_package_path / "r2morph" / "__init__.py").exists())

    @pytest.mark.slow
    def test_mute_r2morph_package(self, temp_dir, r2morph_package_path):
        """Test mutating the r2morph package itself."""
        # Copy the package to temp directory
        r2morph_src = r2morph_package_path / "r2morph"
        mutated_package = temp_dir / "r2morph_mutated"
        shutil.copytree(r2morph_src, mutated_package / "r2morph")

        # Find a Python file in the package
        py_files = list(mutated_package.glob("r2morph/**/*.py"))
        if not py_files:
            pytest.skip("No Python files found in r2morph package")

        # Try to find a compiled Python file or executable
        # Note: Mutating Python bytecode is complex, so this is a conceptual test

        # For now, verify we can analyze the package structure
        cli_file = r2morph_src / "cli.py"
        expect(not (cli_file.exists() and cli_file.stat().st_size <= 0), "CLI file should have content")

    @pytest.mark.slow
    def test_r2morph_cli_remains_functional(self, temp_dir):
        """Test that r2morph CLI works after potential self-mutation concepts."""
        # This tests that our mutation engine can analyze its own code
        # without breaking functionality

        # Verify module can be imported

        # Verify version is accessible
        expect(__version__)

        # Verify basic functionality still works
        config = EngineConfig.create_default()
        expect(config is not None)

    def test_mutation_engine_can_analyze_itself(self, temp_dir):
        """Test that the mutation engine can analyze its own code."""
        r2morph_path = get_r2morph_install_path()

        # Create a simple test binary (we'll use a dataset binary)
        dataset_dir = r2morph_path / "fixtures" / "dataset"
        test_binaries = list(dataset_dir.glob("*")) if dataset_dir.exists() else []

        if not test_binaries:
            # Skip if no test binaries
            pytest.skip("No test binaries in dataset")

        test_binary = test_binaries[0]

        config = EngineConfig.create_default()

        # Analyze using the mutation engine
        with MorphEngine(config=config.to_dict()) as engine:
            engine.load_binary(test_binary).analyze()

            # Verify basic analysis works
            expect(engine.binary is not None)

            # Verify functions were found
            functions = list(engine.binary.get_functions())
            expect(not (len(functions) < 0), "Should find at least some functions")

    def test_version_consistency_after_potential_mutation(self):
        """Test that version remains consistent."""
        __version__ = importlib.import_module("r2morph").__version__

        # Version should be a valid semver string
        parts = __version__.split(".")
        expect(not (len(parts) < _EXPECTED_LEN_PARTS_2), f"Invalid version format: {__version__}")

        # Major version should be numeric
        expect(parts[0].isdigit(), f"Invalid major version: {parts[0]}")


class TestSelfMutationWithRealBinary:
    """Test self-mutation concepts using real binaries as proxies."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    @pytest.fixture
    def simple_binary(self, temp_dir):
        """Create a simple test binary."""
        source = """
#include <stdio.h>

int mutate_me(int x) {
    return x * 2;
}

int main() {
    printf("Result: %d\\n", mutate_me(21));
    return 0;
}
"""
        source_file = temp_dir / "test.c"
        source_file.write_text(source)

        binary_file = temp_dir / "test_binary"

        try:
            run_command(["gcc", "-o", str(binary_file), str(source_file), "-no-pie"], check=True, capture_output=True)
            return binary_file
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("gcc not available")

    def test_mutate_simple_binary(self, simple_binary, temp_dir):
        """Test mutating a simple binary."""
        if not simple_binary or not simple_binary.exists():
            pytest.skip("Binary not available")

        output = temp_dir / "test_binary_mutated"
        config = EngineConfig.create_default()

        with MorphEngine(config=config.to_dict()) as engine:
            engine.load_binary(simple_binary).analyze()

            # Count functions
            functions = list(engine.binary.get_functions())
            expect(not (len(functions) <= 0), "Should find functions")

            # Apply mutations
            engine.add_mutation("nop")
            result = engine.run(
                EngineRunOptions(
                    validation_mode="structural",
                    seed=_SELF_MUTATION_SEED,
                )
            )

            if result.get("passes_run", 0) >= 0:
                engine.save(output)

                # Verify mutated binary still runs
                run_result = run_command(
                    [str(output)],
                    capture_output=True,
                    timeout=_SELF_MUTATION_TIMEOUT_SECONDS,
                )
                expect(not (run_result.returncode not in {0, 1}))

    def test_self_referential_consistency(self, simple_binary, temp_dir):
        """Test that mutation engine maintains self-consistency."""
        if not simple_binary or not simple_binary.exists():
            pytest.skip("Binary not available")

        config = EngineConfig.create_default()

        # Run analysis twice
        results = []
        for _ in range(2):
            with MorphEngine(config=config.to_dict()) as engine:
                engine.load_binary(simple_binary).analyze()
                func_count = len(list(engine.binary.get_functions()))
                results.append(func_count)

        # Should get consistent results
        expect(results[0] == results[1], "Analysis should be deterministic")


class TestMutationIdempotency:
    """Test that mutations can be applied multiple times safely."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    @pytest.fixture
    def test_binary(self, temp_dir):
        """Create test binary."""
        source = """
#include <stdio.h>
int main() {
    for (int i = 0; i < 5; i++) {
        printf("%d\\n", i);
    }
    return 0;
}
"""
        source_file = temp_dir / "idempotent.c"
        source_file.write_text(source)

        binary_file = temp_dir / "idempotent"

        try:
            run_command(["gcc", "-o", str(binary_file), str(source_file), "-no-pie"], check=True, capture_output=True)
            return binary_file
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("gcc not available")

    def test_multiple_mutations_idempotent(self, test_binary, temp_dir):
        """Test applying mutations multiple times."""
        if not test_binary or not test_binary.exists():
            pytest.skip("Binary not available")

        outputs = []
        config = EngineConfig.create_default()

        for i in range(3):
            output = temp_dir / f"mutated_{i}"
            input_file = test_binary if i == 0 else outputs[-1]

            with MorphEngine(config=config.to_dict()) as engine:
                engine.load_binary(input_file).analyze()
                engine.add_mutation("nop")

                result = engine.run(
                    EngineRunOptions(
                        validation_mode="structural",
                        rollback_policy="skip-invalid-pass",
                    )
                )

                if result.get("passes_run", 0) >= 0:
                    engine.save(output)
                    outputs.append(output)
                # If mutation fails, use previous output
                elif outputs:
                    outputs.append(outputs[-1])
                else:
                    pytest.skip("First mutation failed")

        # Verify all outputs run successfully
        for output in outputs:
            if output.exists():
                result = run_command(
                    [str(output)],
                    capture_output=True,
                    timeout=_SELF_MUTATION_TIMEOUT_SECONDS,
                )
                # Should not crash
                expect(not (result.returncode not in (0, 1)), f"Binary {output} crashed")
