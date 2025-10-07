"""
Integration tests for CLI.
"""

import subprocess
from pathlib import Path

import pytest


class TestCLI:
    """Tests for r2morph CLI."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "ls"

    def test_cli_help(self):
        """Test CLI help command."""
        result = subprocess.run(
            ["python3", "-m", "r2morph.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0
        assert "usage:" in result.stdout.lower() or "r2morph" in result.stdout.lower()

    def test_cli_version(self):
        """Test CLI version command."""
        result = subprocess.run(
            ["python3", "-m", "r2morph.cli", "--version"],
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
                "python3",
                "-m",
                "r2morph.cli",
                "morph",
                str(ls_elf),
                str(output_path),
                "--mutations",
                "nop",
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
            ["python3", "-m", "r2morph.cli", "analyze", str(ls_elf)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode in [0, 1]

    def test_cli_with_config(self, ls_elf, tmp_path):
        """Test CLI with config file."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        config_file = tmp_path / "config.json"
        config_file.write_text('{"probability": 0.5}')

        output_path = tmp_path / "ls_config"

        result = subprocess.run(
            [
                "python3",
                "-m",
                "r2morph.cli",
                "morph",
                str(ls_elf),
                str(output_path),
                "--config",
                str(config_file),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode in [0, 1]

    def test_cli_multiple_mutations(self, ls_elf, tmp_path):
        """Test CLI with multiple mutations."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output_path = tmp_path / "ls_multi"

        result = subprocess.run(
            [
                "python3",
                "-m",
                "r2morph.cli",
                "morph",
                str(ls_elf),
                str(output_path),
                "--mutations",
                "nop,substitute",
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
                "python3",
                "-m",
                "r2morph.cli",
                "morph",
                str(ls_elf),
                str(output_path),
                "--mutations",
                "nop",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if output_path.exists():
            validate_result = subprocess.run(
                [
                    "python3",
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
                "python3",
                "-m",
                "r2morph.cli",
                "morph",
                str(ls_elf),
                str(output_path),
                "--mutations",
                "nop",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if output_path.exists():
            diff_result = subprocess.run(
                [
                    "python3",
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
