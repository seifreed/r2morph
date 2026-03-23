from pathlib import Path

from click.testing import CliRunner
from typer.main import get_command

from r2morph.cli import app, analyze as analyze_cmd, functions as functions_cmd

runner = CliRunner()
app_cmd = get_command(app)


def test_cli_help_and_simple_mode(tmp_path):
    result = runner.invoke(app_cmd, ["--help"])
    assert result.exit_code == 0

    binary_path = Path("dataset/elf_x86_64")
    output_path = tmp_path / "elf_simple"

    result = runner.invoke(app_cmd, ["morph", str(binary_path), "-o", str(output_path), "-m", "nop"])
    assert result.exit_code == 0, f"morph failed: {result.output}"
    assert output_path.exists()


def test_cli_direct_analyze_and_functions():
    binary_path = Path("dataset/elf_x86_64")
    analyze_cmd(binary_path, verbose=False)
    functions_cmd(binary_path, limit=5, verbose=False)


def test_cli_direct_morph(tmp_path):
    binary_path = Path("dataset/elf_x86_64")
    output_path = tmp_path / "elf_morphed"

    result = runner.invoke(
        app_cmd,
        ["morph", str(binary_path), "-o", str(output_path), "-m", "nop"],
    )
    assert result.exit_code == 0, f"morph failed: {result.output}"
    assert output_path.exists()
