"""Regression contracts for the supported package and command-line surfaces."""

from __future__ import annotations

import tomllib
from pathlib import Path

from typer.main import get_command

import r2morph
from r2morph.cli import app
from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_PUBLIC_EXPORTS = ("Binary", "MorphEngine", "Pipeline", "__version__")
_PUBLIC_COMMANDS = {
    "analyze",
    "cache",
    "diff",
    "experimental",
    "functions",
    "morph",
    "mutate",
    "report",
    "validate",
    "version",
}
_MUTATE_LONG_OPTIONS = {
    "--aggressive",
    "--allow-limited-symbolic",
    "--cache",
    "--clear-cache",
    "--force",
    "--format",
    "--limited-symbolic-policy",
    "--min-severity",
    "--mutation",
    "--output",
    "--report",
    "--require-pass-severity",
    "--rollback-policy",
    "--runtime-compare-files",
    "--runtime-corpus",
    "--runtime-normalize-whitespace",
    "--runtime-timeout",
    "--seed",
    "--validation-mode",
    "--verbose",
}


def test_package_root_exports_remain_the_supported_python_api() -> None:
    expect(tuple(r2morph.__all__) == _PUBLIC_EXPORTS)


def test_public_package_classes_resolve_from_the_package_root() -> None:
    expect(all(callable(getattr(r2morph, name)) for name in _PUBLIC_EXPORTS[:-1]))


def test_cli_commands_remain_the_supported_top_level_commands() -> None:
    command = get_command(app)

    expect(set(command.commands or {}) == _PUBLIC_COMMANDS)


def test_mutate_command_options_remain_compatible() -> None:
    command = get_command(app).commands["mutate"]
    long_options = {
        option
        for parameter in command.params
        if hasattr(parameter, "opts")
        for option in parameter.opts
        if option.startswith("--")
    }

    expect(long_options == _MUTATE_LONG_OPTIONS)


def test_console_script_remains_bound_to_the_supported_cli_app() -> None:
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    expect(project["scripts"]["r2morph"] == "r2morph.cli:app")
