"""Typed option models and callable adapter for the Typer CLI."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import MISSING, dataclass, fields
from pathlib import Path
from typing import Annotated, Any, get_type_hints

import typer

from r2morph import __version__


class CommandCallback[T]:
    """Expose dataclass fields as a Typer signature and pass one typed value inward."""

    def __init__(self, name: str, model: type[T], handler: Callable[[T], None]) -> None:
        self.__name__ = name
        self.__doc__ = handler.__doc__
        self.__annotations__: dict[str, Any] = {}
        self.__signature__ = _model_signature(model)
        self._model = model
        self._handler = handler

    def __call__(self, **values: Any) -> None:
        self._handler(self._model(**values))


def _show_version(value: bool) -> None:
    if value:
        typer.echo(f"r2morph {__version__}")
        raise typer.Exit()


def _model_signature(model: Any) -> inspect.Signature:
    hints = get_type_hints(model, include_extras=True)
    parameters = []
    for field in fields(model):
        default = inspect.Parameter.empty if field.default is MISSING else field.default
        parameters.append(
            inspect.Parameter(
                field.name,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default=default,
                annotation=hints[field.name],
            )
        )
    return inspect.Signature(parameters)


@dataclass(frozen=True)
class MainCommandOptions:
    ctx: typer.Context
    input_opt: Annotated[
        Path | None,
        typer.Option("--input", "-i", help="Input binary file (alternative style)"),
    ] = None
    output_opt: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output binary file (alternative style)"),
    ] = None
    aggressive: Annotated[bool, typer.Option("--aggressive", "-a", help="Aggressive mode: more mutations")] = False
    force: Annotated[bool, typer.Option("--force", "-f", help="Force mutations to differ from original")] = False
    seed: Annotated[int | None, typer.Option("--seed", help="Deterministic mutation seed")] = None
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose output")] = False
    debug: Annotated[bool, typer.Option("--debug", "-d", help="Enable debug output")] = False
    version: Annotated[
        bool,
        typer.Option("--version", help="Display the installed package version.", callback=_show_version),
    ] = False


@dataclass(frozen=True)
class EnhancedAnalysisOptions:
    binary: Annotated[Path, typer.Argument(help="Path to binary file", exists=True)]
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose output")] = False
    detect_only: Annotated[bool, typer.Option("--detect-only", help="Only run obfuscation detection")] = False
    symbolic: Annotated[bool, typer.Option("--symbolic", help="Enable symbolic execution analysis")] = False
    dynamic: Annotated[bool, typer.Option("--dynamic", help="Enable dynamic instrumentation")] = False
    devirt: Annotated[bool, typer.Option("--devirt", help="Enable devirtualization analysis")] = False
    iterative: Annotated[bool, typer.Option("--iterative", help="Enable iterative simplification")] = False
    rewrite: Annotated[bool, typer.Option("--rewrite", help="Enable binary rewriting")] = False
    bypass: Annotated[bool, typer.Option("--bypass", help="Enable anti-analysis bypass")] = False
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output directory for results")] = None


@dataclass(frozen=True)
class MorphCommandOptions:
    binary: Annotated[Path, typer.Argument(help="Path to binary file", exists=True)]
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output path for morphed binary")] = None
    mutations: Annotated[
        list[str] | None,
        typer.Option("--mutation", "-m", help="Mutations to apply (stable: nop, substitute, register)"),
    ] = None
    aggressive: Annotated[bool, typer.Option("--aggressive", "-a", help="Aggressive mode: more mutations")] = False
    force: Annotated[bool, typer.Option("--force", "-f", help="Force mutations to differ from original")] = False
    validation_mode: Annotated[
        str,
        typer.Option("--validation-mode", help="structural, runtime, symbolic, off"),
    ] = "structural"
    allow_limited_symbolic: Annotated[
        bool,
        typer.Option("--allow-limited-symbolic", help="Allow passes with limited symbolic support"),
    ] = False
    limited_symbolic_policy: Annotated[
        str,
        typer.Option("--limited-symbolic-policy", help="block, degrade-runtime, degrade-structural"),
    ] = "block"
    rollback_policy: Annotated[
        str,
        typer.Option("--rollback-policy", help="fail-fast, skip-invalid-pass, skip-invalid-mutation"),
    ] = "skip-invalid-pass"
    report: Annotated[Path | None, typer.Option("--report", help="Write a machine-readable JSON report")] = None
    runtime_corpus: Annotated[
        Path | None,
        typer.Option("--runtime-corpus", help="Optional JSON corpus for runtime validation"),
    ] = None
    runtime_compare_files: Annotated[
        bool,
        typer.Option("--runtime-compare-files", help="Compare monitored files during runtime validation"),
    ] = False
    runtime_normalize_whitespace: Annotated[
        bool,
        typer.Option("--runtime-normalize-whitespace", help="Ignore trailing whitespace differences"),
    ] = False
    runtime_timeout: Annotated[int, typer.Option("--runtime-timeout", help="Timeout per runtime test in seconds")] = 10
    min_severity: Annotated[
        str | None,
        typer.Option("--min-severity", help="Minimum required final-report pass severity"),
    ] = None
    require_pass_severity: Annotated[
        list[str] | None,
        typer.Option("--require-pass-severity", help="Require PassName=severity in the final report"),
    ] = None
    seed: Annotated[int | None, typer.Option("--seed", help="Deterministic mutation seed")] = None
    cache: Annotated[bool, typer.Option("--cache", help="Enable analysis caching")] = False
    clear_cache: Annotated[bool, typer.Option("--clear-cache", help="Clear analysis cache before running")] = False
    report_format: Annotated[str, typer.Option("--format", help="Report format: json or sarif")] = "json"
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose output")] = False


@dataclass(frozen=True)
class ValidateCommandOptions:
    original: Annotated[Path, typer.Argument(help="Original binary", exists=True)]
    mutated: Annotated[Path, typer.Argument(help="Mutated binary", exists=True)]
    corpus: Annotated[
        Path | None,
        typer.Option("--corpus", help="Optional JSON runtime test corpus"),
    ] = None
    compare_files: Annotated[bool, typer.Option("--compare-files", help="Compare monitored output files")] = False
    normalize_whitespace: Annotated[
        bool,
        typer.Option("--normalize-whitespace", help="Ignore trailing whitespace differences"),
    ] = False
    timeout: Annotated[int, typer.Option("--timeout", help="Timeout per test case in seconds")] = 10


@dataclass(frozen=True)
class ReportViewOptions:
    report_file: Annotated[Path, typer.Argument(help="Report JSON generated by mutate", exists=True)]
    only_pass: Annotated[str | None, typer.Option("--only-pass", help="Filter mutations by pass name")] = None
    only_status: Annotated[str | None, typer.Option("--only-status", help="Filter by symbolic status")] = None
    only_mismatches: Annotated[bool, typer.Option("--only-mismatches", help="Show symbolic mismatches only")] = False
    summary_only: Annotated[bool, typer.Option("--summary-only", help="Print only the textual summary")] = False
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write filtered JSON to a file")] = None
    require_results: Annotated[bool, typer.Option("--require-results", help="Fail when the view is empty")] = False
    min_severity: Annotated[str | None, typer.Option("--min-severity", help="Require a minimum pass severity")] = None
    only_expected_severity: Annotated[
        str | None,
        typer.Option("--only-expected-severity", help="Filter gate failures by expected severity"),
    ] = None
    only_pass_failure: Annotated[
        str | None,
        typer.Option("--only-pass-failure", help="Filter gate failures by pass name"),
    ] = None
    only_degraded: Annotated[bool, typer.Option("--only-degraded", help="Show degraded validation modes only")] = False
    only_failed_gates: Annotated[bool, typer.Option("--only-failed-gates", help="Show failed CLI gates only")] = False
    only_risky_passes: Annotated[bool, typer.Option("--only-risky-passes", help="Show risky passes only")] = False
    only_structural_risk: Annotated[
        bool,
        typer.Option("--only-structural-risk", help="Show structural risks only"),
    ] = False
    only_symbolic_risk: Annotated[bool, typer.Option("--only-symbolic-risk", help="Show symbolic risks only")] = False
    only_clean_passes: Annotated[bool, typer.Option("--only-clean-passes", help="Show clean passes only")] = False
    only_covered_passes: Annotated[
        bool,
        typer.Option("--only-covered-passes", help="Show covered clean passes only"),
    ] = False
    only_uncovered_passes: Annotated[
        bool,
        typer.Option("--only-uncovered-passes", help="Show uncovered clean passes only"),
    ] = False
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format: json or sarif")] = "json"
