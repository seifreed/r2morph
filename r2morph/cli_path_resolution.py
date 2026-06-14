"""Pure helpers for CLI path resolution and usage text."""

from __future__ import annotations

from pathlib import Path


def resolve_main_cli_paths(
    input_opt: Path | None,
    output_opt: Path | None,
    positional_args: list[str],
) -> tuple[Path | None, Path | None]:
    """Resolve the effective CLI input/output paths from options and positionals."""
    input_file = input_opt
    output_file = output_opt

    if input_file is None and positional_args:
        input_file = Path(positional_args[0])
        if len(positional_args) > 1:
            output_file = Path(positional_args[1])

    return input_file, output_file


def build_missing_input_help_lines() -> list[str]:
    """Return the usage lines shown when the CLI is invoked without input."""
    return [
        "[yellow]No input file provided.[/yellow]",
        "\nUsage:",
        "  Simple:   [cyan]r2morph input.exe [output.exe][/cyan]",
        "  Alternative:   [cyan]r2morph -i input.exe -o output.exe[/cyan]",
        "  Aggressive: [cyan]r2morph -i input.exe -o output.exe --aggressive[/cyan]",
        "\nRun [cyan]r2morph --help[/cyan] for more options",
    ]
