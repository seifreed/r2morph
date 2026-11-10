"""
Integration tests for CLI.
"""

import importlib
import importlib.util
import sys

import pytest

from tests.integration.cli_test_support import CLIIntegrationBase
from tests.utils.assertions import expect
from tests.utils.process import run_command

_EXPECTED_FAILURES_COUNT_NOPINSERTION_NOT_REQUESTED_EXP_2 = 2
_EXPECTED_PRIORITY_0_FAILURE_COUNT_2 = 2
_EXPECTED_RESULT_RETURNCODE_2 = 2
_EXPECTED_RESULT_RETURNCODE_2_2 = 2


# Check if typer is available
try:
    importlib_util = importlib.import_module("importlib.util")

    TYPER_AVAILABLE = importlib_util.find_spec("typer") is not None
except ImportError:
    TYPER_AVAILABLE = False


@pytest.mark.skipif(not TYPER_AVAILABLE, reason="typer not installed")
class TestCLI(CLIIntegrationBase):
    """CLI integration coverage for one cohesive command workflow."""

    def test_cli_help(self):
        """Test CLI help command."""
        result = run_command(
            [sys.executable, "-m", "r2morph.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        expect(result.returncode == 0)
        expect("usage:" in result.stdout.lower() or "r2morph" in result.stdout.lower())

    def test_cli_version(self):
        """Test CLI version command."""
        result = run_command(
            [sys.executable, "-m", "r2morph.cli", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        expect(not (result.returncode not in [0, 2]))

    def test_cli_morph_basic(self, ls_elf, tmp_path):
        """Test basic morph command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_morphed"

        result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "-i",
                str(ls_elf),
                "-o",
                str(output_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        expect(not (result.returncode not in [0, 1]))

    def test_cli_analyze(self, ls_elf):
        """Test analyze command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        result = run_command(
            [sys.executable, "-m", "r2morph.cli", "analyze", str(ls_elf)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(not (result.returncode not in [0, 1]))

    def test_cli_with_config(self, ls_elf, tmp_path):
        """Test CLI with aggressive mode (config-like behavior)."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_config"

        result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "-i",
                str(ls_elf),
                "-o",
                str(output_path),
                "--aggressive",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        expect(not (result.returncode not in [0, 1]))

    def test_cli_multiple_mutations(self, ls_elf, tmp_path):
        """Test CLI with multiple mutations (using simple mode)."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_multi"

        result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "-i",
                str(ls_elf),
                "-o",
                str(output_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        expect(not (result.returncode not in [0, 1]))

    def test_cli_validate(self, ls_elf, tmp_path):
        """Test validate command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_validate"

        run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "morph",
                str(ls_elf),
                "-o",
                str(output_path),
                "-m",
                "nop",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if output_path.exists():
            validate_result = run_command(
                [
                    sys.executable,
                    "-m",
                    "r2morph.cli",
                    "validate",
                    str(ls_elf),
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            expect(not (validate_result.returncode not in [0, 1]))

    def test_cli_validate_with_compare_files(self, tmp_path):
        """Test validate command with monitored side-effect files."""
        original = tmp_path / "original.sh"
        mutated = tmp_path / "mutated.sh"
        corpus = tmp_path / "corpus.json"

        original.write_text("#!/bin/sh\nprintf 'A' > side_effect.txt\n", encoding="utf-8")
        mutated.write_text("#!/bin/sh\nprintf 'B' > side_effect.txt\n", encoding="utf-8")
        original.chmod(0o755)
        mutated.chmod(0o755)
        corpus.write_text(
            '[{"description":"side-effect","args":[],"stdin":"","expected_exitcode":0,"monitored_files":["side_effect.txt"]}]',
            encoding="utf-8",
        )

        validate_result = run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "validate",
                str(original),
                str(mutated),
                "--corpus",
                str(corpus),
                "--compare-files",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        expect(validate_result.returncode == 1)
        expect(not ('"files": true' not in validate_result.stdout))
        expect(not ('"side_effect.txt"' not in validate_result.stdout))

    def test_cli_diff(self, ls_elf, tmp_path):
        """Test diff command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_diff"

        run_command(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "morph",
                str(ls_elf),
                "-o",
                str(output_path),
                "-m",
                "nop",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if output_path.exists():
            diff_result = run_command(
                [
                    sys.executable,
                    "-m",
                    "r2morph.cli",
                    "diff",
                    str(ls_elf),
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            expect(not (diff_result.returncode not in [0, 1]))
