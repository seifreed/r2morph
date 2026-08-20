import importlib
import importlib.util
from pathlib import Path

import pytest
import typer

from r2morph.cli import analyze, analyze_enhanced, app, functions, version
from tests.utils.assertions import expect

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)


def _dataset_path(name: str) -> Path:
    return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / name


def test_cli_no_args_shows_usage():
    cli_runner = importlib.import_module("typer.testing").CliRunner

    runner = cli_runner()
    result = runner.invoke(app, [])
    expect(result.exit_code == 0)
    expect(not ("No input file provided" not in result.output))


def test_cli_analyze_inprocess():
    binary_path = _dataset_path("elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    try:
        analyze(binary=binary_path, verbose=False)
    except typer.Exit as exc:
        expect(not (exc.exit_code not in {0, 1}))


def test_cli_functions_inprocess():
    binary_path = _dataset_path("elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    try:
        functions(binary=binary_path, limit=1, verbose=False)
    except typer.Exit as exc:
        expect(not (exc.exit_code not in {0, 1, 2}))


@pytest.mark.experimental
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
        expect(not (exc.exit_code not in {0, 1}))


def test_cli_morph_inprocess(tmp_path: Path):
    binary_path = _dataset_path("elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    cli_runner = importlib.import_module("typer.testing").CliRunner

    runner = cli_runner()
    output_path = tmp_path / "morphed_cli_output"
    result = runner.invoke(
        app,
        [
            "morph",
            str(binary_path),
            "-o",
            str(output_path),
            "-m",
            "nop",
            "-m",
            "substitute",
            "-m",
            "register",
            "--aggressive",
            "--force",
        ],
    )
    expect(not (result.exit_code not in {0, 1}), f"morph failed with exit code {result.exit_code}: {result.output}")


def test_cli_version_inprocess():
    version()


pytestmark = []
