import importlib.util
from pathlib import Path

import pytest
import typer

from r2morph.cli import app, analyze, analyze_enhanced, functions, morph, version


if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)


def _dataset_path(name: str) -> Path:
    return Path(__file__).parent.parent.parent / "dataset" / name


def test_cli_no_args_shows_usage():
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "No input file provided" in result.output


def test_cli_analyze_inprocess():
    binary_path = _dataset_path("elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    try:
        analyze(binary=binary_path, verbose=False)
    except typer.Exit as exc:
        assert exc.exit_code in {0, 1}


def test_cli_functions_inprocess():
    binary_path = _dataset_path("elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    try:
        functions(binary=binary_path, limit=1, verbose=False)
    except typer.Exit as exc:
        assert exc.exit_code in {0, 1, 2}


def test_cli_analyze_enhanced_detect_only(tmp_path: Path):
    binary_path = _dataset_path("elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    try:
        analyze_enhanced(
            binary=binary_path,
            verbose=False,
            detect_only=True,
            symbolic=False,
            dynamic=False,
            devirt=False,
            iterative=False,
            rewrite=False,
            bypass=False,
            output=tmp_path,
        )
    except typer.Exit as exc:
        assert exc.exit_code in {0, 1}


def test_cli_morph_inprocess(tmp_path: Path):
    binary_path = _dataset_path("elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    output_path = tmp_path / "morphed_cli_output"
    try:
        morph(
            binary=binary_path,
            output=output_path,
            mutations=["nop", "substitute", "register", "expand", "block"],
            aggressive=True,
            force=True,
            verbose=False,
        )
    except typer.Exit as exc:
        assert exc.exit_code in {0, 1}


def test_cli_version_inprocess():
    version()
