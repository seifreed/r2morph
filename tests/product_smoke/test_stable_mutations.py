"""
Product smoke tests for stable mutations.

These tests verify the core product flow:
- load binary -> apply mutation -> validate -> export

Tests are marked with @pytest.mark.stable for CI filtering.
"""

import subprocess
import sys
from pathlib import Path

import pytest


STABLE_MUTATIONS = ["nop", "substitute", "register"]
EXPERIMENTAL_MUTATIONS = ["expand", "block"]


@pytest.fixture
def test_binary() -> Path:
    """Stable ELF x86_64 binary for product tests."""
    binary = Path("dataset/elf_x86_64")
    if not binary.exists():
        pytest.skip("ELF test binary not available")
    return binary


@pytest.mark.stable
@pytest.mark.product_smoke
class TestStableMutations:
    """Product acceptance tests for stable mutation passes."""

    def test_nop_mutation_produces_output(self, test_binary, tmp_path):
        """NOP insertion should produce a modified binary."""
        output_path = tmp_path / "output_nop.bin"
        report_path = tmp_path / "report_nop.json"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "mutate",
                str(test_binary),
                "-o",
                str(output_path),
                "-m",
                "nop",
                "--seed",
                "1337",
                "--report",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode == 0, f"Mutate failed: {result.stderr}"
        assert output_path.exists(), "Output binary not created"
        assert output_path.stat().st_size > 0, "Output binary is empty"
        assert report_path.exists(), "Report not created"

    def test_substitute_mutation_produces_output(self, test_binary, tmp_path):
        """Instruction substitution should produce a modified binary."""
        output_path = tmp_path / "output_substitute.bin"
        report_path = tmp_path / "report_substitute.json"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "mutate",
                str(test_binary),
                "-o",
                str(output_path),
                "-m",
                "substitute",
                "--seed",
                "1337",
                "--report",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode == 0, f"Mutate failed: {result.stderr}"
        assert output_path.exists(), "Output binary not created"

    def test_register_mutation_produces_output(self, test_binary, tmp_path):
        """Register substitution should produce a modified binary."""
        output_path = tmp_path / "output_register.bin"
        report_path = tmp_path / "report_register.json"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "mutate",
                str(test_binary),
                "-o",
                str(output_path),
                "-m",
                "register",
                "--seed",
                "1337",
                "--report",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode == 0, f"Mutate failed: {result.stderr}"
        assert output_path.exists(), "Output binary not created"

    def test_all_stable_mutations_together(self, test_binary, tmp_path):
        """All stable mutations should run together."""
        output_path = tmp_path / "output_all.bin"
        report_path = tmp_path / "report_all.json"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "mutate",
                str(test_binary),
                "-o",
                str(output_path),
                "-m",
                "nop",
                "-m",
                "substitute",
                "-m",
                "register",
                "--seed",
                "1337",
                "--report",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

        assert result.returncode == 0, f"Mutate failed: {result.stderr}"
        assert output_path.exists(), "Output binary not created"

    @pytest.mark.parametrize("mutation", STABLE_MUTATIONS)
    def test_stable_mutation_with_validation(self, test_binary, tmp_path, mutation):
        """Each stable mutation should work with structural validation."""
        output_path = tmp_path / f"output_{mutation}.bin"
        report_path = tmp_path / f"report_{mutation}.json"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "mutate",
                str(test_binary),
                "-o",
                str(output_path),
                "-m",
                mutation,
                "--validation-mode",
                "structural",
                "--seed",
                "1337",
                "--report",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode == 0, f"{mutation} mutation failed: {result.stderr}"

    def test_report_contains_passes(self, test_binary, tmp_path):
        """Report should contain all applied passes."""
        output_path = tmp_path / "output.bin"
        report_path = tmp_path / "report.json"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "mutate",
                str(test_binary),
                "-o",
                str(output_path),
                "-m",
                "nop",
                "-m",
                "substitute",
                "--seed",
                "1337",
                "--report",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode == 0

        import json

        report = json.loads(report_path.read_text())
        passes = list(report.get("passes", {}).keys())
        assert "NopInsertion" in passes or "nop" in str(passes)
        assert "InstructionSubstitution" in passes or "substitute" in str(passes)


@pytest.mark.experimental
@pytest.mark.product_smoke
class TestExperimentalMutations:
    """Product tests for experimental mutation passes."""

    @pytest.mark.parametrize("mutation", EXPERIMENTAL_MUTATIONS)
    def test_experimental_mutation_warns(self, test_binary, tmp_path, mutation):
        """Experimental mutations should warn but still run."""
        output_path = tmp_path / f"output_{mutation}.bin"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "mutate",
                str(test_binary),
                "-o",
                str(output_path),
                "-m",
                mutation,
                "--seed",
                "1337",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Experimental mutations should warn
        assert "experimental" in result.stdout.lower() or "Experimental" in result.stdout
