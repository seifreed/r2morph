from __future__ import annotations

from pathlib import Path

import pytest
typer_testing = pytest.importorskip("typer.testing")
CliRunner = typer_testing.CliRunner

from r2morph import cli


def test_cli_simple_mode(tmp_path: Path) -> None:
    runner = CliRunner()
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    input_path = tmp_path / "input.bin"
    output_path = tmp_path / "output.bin"
    input_path.write_bytes(source.read_bytes())

    result = runner.invoke(cli.app, [str(input_path), str(output_path)])
    assert result.exit_code == 0
    assert output_path.exists()


def test_cli_no_input_shows_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli.app, [])
    assert result.exit_code == 0
    assert "No input file provided" in result.output


def test_cli_version_function() -> None:
    result = cli.version()
    assert result is None
