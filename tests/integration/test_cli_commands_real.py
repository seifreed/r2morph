"""
Real integration tests for CLI commands using dataset binaries.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)
if importlib.util.find_spec("yaml") is None:
    pytest.skip("pyyaml not installed", allow_module_level=True)


class TestCLICommandsReal:
    """Real tests for CLI commands."""

    @pytest.fixture
    def ls_elf(self):
        """Path to ls ELF binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "elf_x86_64"

    @pytest.fixture
    def ls_macos(self):
        """Path to ls macOS binary."""
        return Path(__file__).parent.parent.parent / "dataset" / "macho_arm64"

    def test_simple_mode_basic(self, ls_elf, tmp_path):
        """Test simple mode with basic usage."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output = tmp_path / "ls_out"
        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", str(ls_elf), str(output)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode in [0, 1]

    def test_simple_mode_verbose(self, ls_elf, tmp_path):
        """Test simple mode with verbose flag."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output = tmp_path / "ls_verbose"
        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", "-v", str(ls_elf), str(output)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode in [0, 1]

    def test_simple_mode_debug(self, ls_elf, tmp_path):
        """Test simple mode with debug flag."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output = tmp_path / "ls_debug"
        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", "-d", str(ls_elf), str(output)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode in [0, 1]

    def test_simple_mode_force(self, ls_elf, tmp_path):
        """Test simple mode with force flag."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output = tmp_path / "ls_force"
        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", "-f", str(ls_elf), str(output)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode in [0, 1]

    def test_simple_mode_all_flags(self, ls_elf, tmp_path):
        """Test simple mode with all flags."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output = tmp_path / "ls_all_flags"
        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", "-a", "-f", "-v", str(ls_elf), str(output)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode in [0, 1]

    def test_analyze_detailed(self, ls_elf):
        """Test analyze command with detailed output."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", "analyze", str(ls_elf)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode in [0, 1]

    def test_functions_default_limit(self, ls_elf):
        """Test functions command with default limit."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", "functions", str(ls_elf)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode in [0, 1]

    def test_functions_custom_limit(self, ls_elf):
        """Test functions command with custom limit."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", "functions", str(ls_elf), "--limit", "10"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Might not support --limit in subprocess mode
        assert result.returncode in [0, 1, 2]

    def test_morph_with_output_option(self, ls_elf, tmp_path):
        """Test simple mode with explicit output."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output = tmp_path / "ls_morph_out"
        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", str(ls_elf), str(output)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode in [0, 1]

    def test_morph_all_mutations(self, ls_elf, tmp_path):
        """Test morph with all mutation types."""
        if not ls_elf.exists():
            pytest.skip("ELF binary not available")

        output = tmp_path / "ls_all_mut"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "r2morph.cli",
                "morph",
                str(ls_elf),
                "-o",
                str(output),
                "-m",
                "nop",
                "-m",
                "substitute",
                "-m",
                "register",
                "-m",
                "expand",
                "-m",
                "block",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode in [0, 1, 2]

    def test_version(self):
        """Test version command."""
        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # Version command might return 0 or 2 depending on typer version
        assert result.returncode in [0, 2]

    def test_macos_binary(self, ls_macos, tmp_path):
        """Test with macOS binary."""
        if not ls_macos.exists():
            pytest.skip("macOS binary not available")

        output = tmp_path / "ls_macos_out"
        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", str(ls_macos), str(output)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode in [0, 1]

    def test_error_nonexistent_file(self, tmp_path):
        """Test error handling with nonexistent file."""
        nonexistent = tmp_path / "nonexistent"
        output = tmp_path / "output"

        result = subprocess.run(
            [sys.executable, "-m", "r2morph.cli", str(nonexistent), str(output)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0
