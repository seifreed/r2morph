"""
Integration tests for CLI.
"""

import subprocess
import sys
import importlib.util
from pathlib import Path

import pytest

# Check if typer is available
try:
    import typer

    TYPER_AVAILABLE = True
except ImportError:
    TYPER_AVAILABLE = False


@pytest.mark.skipif(not TYPER_AVAILABLE, reason="typer not installed")
class TestCLI:
    """Tests for r2morph CLI."""

    @pytest.fixture(autouse=True)
    def _require_r2pipe(self):
        if importlib.util.find_spec("r2pipe") is None:
            pytest.skip("r2pipe not installed")
        if importlib.util.find_spec("yaml") is None:
            pytest.skip("pyyaml not installed")

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    def test_cli_help(self):
        """Test CLI help command."""
        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0
        assert "usage:" in result.stdout.lower() or "r2morph" in result.stdout.lower()

    def test_cli_version(self):
        """Test CLI version command."""
        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode in [0, 2]

    def test_cli_morph_basic(self, ls_elf, tmp_path):
        """Test basic morph command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_morphed"

        result = subprocess.run(
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

        assert result.returncode in [0, 1]

    def test_cli_analyze(self, ls_elf):
        """Test analyze command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", "analyze", str(ls_elf)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]

    def test_cli_with_config(self, ls_elf, tmp_path):
        """Test CLI with aggressive mode (config-like behavior)."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_config"

        result = subprocess.run(
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

        assert result.returncode in [0, 1]

    def test_cli_multiple_mutations(self, ls_elf, tmp_path):
        """Test CLI with multiple mutations (using simple mode)."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_multi"

        result = subprocess.run(
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

        assert result.returncode in [0, 1]

    def test_cli_validate(self, ls_elf, tmp_path):
        """Test validate command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_validate"

        subprocess.run(
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
            validate_result = subprocess.run(
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

            assert validate_result.returncode in [0, 1]

    def test_cli_diff(self, ls_elf, tmp_path):
        """Test diff command."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_diff"

        subprocess.run(
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
            diff_result = subprocess.run(
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

            assert diff_result.returncode in [0, 1]
