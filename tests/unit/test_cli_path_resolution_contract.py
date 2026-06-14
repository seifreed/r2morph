from __future__ import annotations

from pathlib import Path

from r2morph.cli_path_resolution import (
    build_missing_input_help_lines,
    resolve_main_cli_paths,
)


def test_cli_path_resolution_prefers_explicit_options() -> None:
    input_path = Path("input.bin")
    output_path = Path("output.bin")

    resolved_input, resolved_output = resolve_main_cli_paths(
        input_path,
        output_path,
        ["positional-in.bin", "positional-out.bin"],
    )

    assert resolved_input == input_path
    assert resolved_output == output_path


def test_cli_path_resolution_uses_positionals_when_options_missing() -> None:
    resolved_input, resolved_output = resolve_main_cli_paths(
        None,
        None,
        ["positional-in.bin", "positional-out.bin"],
    )

    assert resolved_input == Path("positional-in.bin")
    assert resolved_output == Path("positional-out.bin")


def test_cli_path_resolution_help_lines_are_stable() -> None:
    assert build_missing_input_help_lines() == [
        "[yellow]No input file provided.[/yellow]",
        "\nUsage:",
        "  Simple:   [cyan]r2morph input.exe [output.exe][/cyan]",
        "  Alternative:   [cyan]r2morph -i input.exe -o output.exe[/cyan]",
        "  Aggressive: [cyan]r2morph -i input.exe -o output.exe --aggressive[/cyan]",
        "\nRun [cyan]r2morph --help[/cyan] for more options",
    ]
