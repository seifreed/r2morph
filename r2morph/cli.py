"""
Command-line interface for r2morph.

Primary product flow:
    r2morph input.bin [output.bin]
    r2morph mutate input.bin -o output.bin --report report.json
"""

import argparse
import json
import sys
import traceback
from importlib import import_module
from pathlib import Path
from typing import Annotated, Any, cast

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from r2morph import __version__
from r2morph.cli_cache_command import handle_cache_command
from r2morph.cli_options import (
    CommandCallback,
    EnhancedAnalysisOptions,
    MainCommandOptions,
    MorphCommandOptions,
    ReportViewOptions,
    ValidateCommandOptions,
)
from r2morph.cli_output_helpers import (
    build_binary_analysis_rows,
    build_function_limit_notice,
    build_function_rows,
)
from r2morph.cli_path_resolution import (
    build_missing_input_help_lines,
    resolve_main_cli_paths,
)
from r2morph.cli_workflows import (
    MorphWorkflowRequest,
    SimpleModeRequest,
    _build_runtime_validator,
    _run_morph_workflow,
    _run_simple_mode,
)
from r2morph.core.engine import MorphEngine
from r2morph.core.support import PRODUCT_SUPPORT
from r2morph.reporting.cli_commands import ReportCommandOptions, handle_report_command
from r2morph.reporting.report_context import PassClassFilters
from r2morph.utils.logging import setup_logging

app = typer.Typer(
    name="r2morph",
    help="Metamorphic mutation engine with structured validation and reporting",
    add_completion=False,
    invoke_without_command=True,
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
experimental_app = typer.Typer(
    name="experimental",
    help="Secondary experimental commands outside the stable mutation engine surface",
    add_completion=False,
)
app.add_typer(experimental_app, name="experimental")
console = Console()

KNOWN_COMMANDS = {
    "analyze",
    "functions",
    "morph",
    "mutate",
    "validate",
    "diff",
    "report",
    "version",
    "cache",
}


def _load_binary_analyzer() -> type[Any]:
    """Lazy import for analysis-only flows outside the stable mutate/report path."""
    return cast(type[Any], import_module("r2morph.analysis.analyzer").BinaryAnalyzer)


def _load_diff_analyzer() -> type[Any]:
    """Lazy import for diff-only flows outside the stable mutate/report hot path."""
    return cast(type[Any], import_module("r2morph.analysis.diff_analyzer").DiffAnalyzer)


def _handle_main(options: MainCommandOptions) -> None:
    """
    r2morph - mutation engine with validation

    SIMPLE USAGE (like r2morph):
        r2morph input.exe [output.exe]
        r2morph -i input.exe -o output.exe

    This applies the stable mutation set:
    nop + substitute + register, then validates and writes a report.

    AGGRESSIVE MODE:
        r2morph -i input.exe -o output.exe --aggressive
        r2morph input.exe output.exe -a

    ADVANCED USAGE:
        r2morph analyze input.exe
        r2morph functions input.exe
        r2morph morph input.exe -m nop
    """
    if options.ctx.invoked_subcommand is not None:
        return

    input_file, output_file = resolve_main_cli_paths(
        options.input_opt,
        options.output_opt,
        [arg for arg in options.ctx.args if not arg.startswith("-")],
    )

    if input_file is None:
        for line in build_missing_input_help_lines():
            console.print(line)
        raise typer.Exit(0)

    try:
        _run_simple_mode(
            SimpleModeRequest(
                input_file=input_file,
                output_file=output_file,
                aggressive=options.aggressive,
                force=options.force,
                seed=options.seed,
                verbose=options.verbose,
                debug=options.debug,
            )
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        if options.verbose or options.debug:
            console.print(traceback.format_exc())
        raise typer.Exit(1) from e


main_callback = CommandCallback("main_callback", MainCommandOptions, _handle_main)
app.callback()(main_callback)


@app.command()
def analyze(
    binary: Annotated[Path, typer.Argument(help="Path to binary file", exists=True)],
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
) -> None:
    """
    Analyze a binary and display statistics.
    """
    setup_logging("DEBUG" if verbose else "INFO")

    with console.status("[bold green]Analyzing binary..."):
        try:
            binary_analyzer_cls = _load_binary_analyzer()
            with MorphEngine() as engine:
                engine.load_binary(binary).analyze()
                analyzer = binary_analyzer_cls(engine.binary)
                stats = analyzer.get_statistics()

            table = Table(title=f"Binary Analysis: {binary.name}")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            for label, value in build_binary_analysis_rows(stats):
                table.add_row(label, value)

            console.print(table)

        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1) from e


def _handle_enhanced_analysis(options: EnhancedAnalysisOptions) -> None:
    """
    Experimental analysis for obfuscated binaries (secondary workflow).
    Requires enhanced dependencies: pip install 'r2morph[enhanced]'

    Phase 2 capabilities include:
    - Advanced packer detection (20+ packers)
    - Control Flow Obfuscation simplification
    - Iterative multi-pass simplification
    - Binary rewriting and reconstruction
    - Anti-analysis bypass framework
    """
    setup_logging("DEBUG" if options.verbose else "INFO")

    analyzer_module = import_module("r2morph.analysis.enhanced_analyzer")
    models_module = import_module("r2morph.analysis.enhanced_analyzer_models")
    enhanced_analysis_orchestrator = analyzer_module.EnhancedAnalysisOrchestrator
    check_enhanced_dependencies = analyzer_module.check_enhanced_dependencies
    analysis_options = models_module.AnalysisOptions

    if not check_enhanced_dependencies():
        console.print("[bold red]Error:[/bold red] Enhanced analysis requires additional dependencies.")
        console.print("Install with: [cyan]pip install 'r2morph[enhanced]'[/cyan]")
        raise typer.Exit(1)

    with console.status("[bold green]Analyzing obfuscated binary..."):
        try:
            analysis_configuration = analysis_options(
                verbose=options.verbose,
                detect_only=options.detect_only,
                symbolic=options.symbolic,
                dynamic=options.dynamic,
                devirt=options.devirt,
                iterative=options.iterative,
                rewrite=options.rewrite,
                bypass=options.bypass,
            )

            orchestrator = enhanced_analysis_orchestrator(
                binary_path=options.binary,
                output_dir=options.output,
                console=console,
            )

            orchestrator.analyze(analysis_configuration)

        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            if options.verbose:
                console.print(traceback.format_exc())
            raise typer.Exit(1) from e


analyze_enhanced = CommandCallback("analyze_enhanced", EnhancedAnalysisOptions, _handle_enhanced_analysis)
experimental_app.command("analyze-enhanced")(analyze_enhanced)


@app.command()
def functions(
    binary: Annotated[Path, typer.Argument(help="Path to binary file", exists=True)],
    limit: int = typer.Option(20, "--limit", "-l", help="Maximum functions to display"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
) -> None:
    """
    List functions in a binary.
    """
    setup_logging("DEBUG" if verbose else "INFO")

    with console.status("[bold green]Loading binary..."):
        try:
            binary_analyzer_cls = _load_binary_analyzer()
            with MorphEngine() as engine:
                engine.load_binary(binary).analyze()
                analyzer = binary_analyzer_cls(engine.binary)
                funcs = analyzer.get_functions_list()

            table = Table(title=f"Functions in {binary.name}")
            table.add_column("Address", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Size", style="yellow")
            table.add_column("Instructions", style="magenta")

            for address, name, size, instruction_count in build_function_rows(funcs, limit=limit):
                table.add_row(address, name, size, instruction_count)

            console.print(table)

            notice = build_function_limit_notice(limit, len(funcs))
            if notice is not None:
                console.print(f"\n[yellow]{notice}[/yellow]")

        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1) from e


def _handle_morph(options: MorphCommandOptions) -> None:
    """
    Apply tracked mutations to a binary and validate the result.

    Examples:
        r2morph mutate binary.exe -o output.exe
        r2morph mutate binary.exe -m nop -m substitute --report report.json
        r2morph mutate binary.exe --cache  # Enable caching for faster repeated runs
    """
    setup_logging("DEBUG" if options.verbose else "INFO")

    output = options.output or options.binary.parent / f"{options.binary.stem}_morphed{options.binary.suffix}"

    if options.clear_cache:
        analysis_cache = import_module("r2morph.core.analysis_cache").AnalysisCache
        cleared = analysis_cache().clear()
        console.print(f"[cyan]Cleared {cleared} cache entries[/cyan]")

    selected_mutations = options.mutations or ["nop", "substitute", "register"]
    unknown = [
        m
        for m in selected_mutations
        if m not in set(PRODUCT_SUPPORT.stable_mutations) | set(PRODUCT_SUPPORT.experimental_mutations)
    ]
    if unknown:
        console.print(f"[bold red]Error:[/bold red] Unknown mutations: {', '.join(unknown)}")
        raise typer.Exit(2)

    _run_morph_workflow(
        MorphWorkflowRequest(
            binary=options.binary,
            output=output,
            mutations=selected_mutations,
            aggressive=options.aggressive,
            force=options.force,
            validation_mode=options.validation_mode,
            allow_limited_symbolic=options.allow_limited_symbolic,
            limited_symbolic_policy=options.limited_symbolic_policy,
            rollback_policy=options.rollback_policy,
            report=options.report,
            runtime_corpus=options.runtime_corpus,
            runtime_compare_files=options.runtime_compare_files,
            runtime_normalize_whitespace=options.runtime_normalize_whitespace,
            runtime_timeout=options.runtime_timeout,
            min_severity=options.min_severity,
            require_pass_severity=options.require_pass_severity,
            seed=options.seed,
            report_format=options.report_format,
        )
    )


morph = CommandCallback("morph", MorphCommandOptions, _handle_morph)
app.command()(morph)
app.command(name="mutate")(morph)


def _handle_validate(options: ValidateCommandOptions) -> None:
    """
    Run runtime validation for an original/mutated binary pair.

    Corpus schema:
        [
          {
            "description": "default-exec",
            "args": [],
            "stdin": "",
            "expected_exitcode": 0,
            "env": {},
            "working_dir": null,
            "monitored_files": []
          }
        ]
    """
    validator = _build_runtime_validator(
        timeout=options.timeout,
        corpus=options.corpus,
        compare_files=options.compare_files,
        normalize_whitespace=options.normalize_whitespace,
    )
    result = validator.validate(options.original, options.mutated)
    console.print_json(json.dumps(result.to_dict()))
    raise typer.Exit(0 if result.passed else 1)


validate = CommandCallback("validate", ValidateCommandOptions, _handle_validate)
app.command()(validate)


@app.command()
def diff(
    original: Annotated[Path, typer.Argument(help="Original binary", exists=True)],
    mutated: Annotated[Path, typer.Argument(help="Mutated binary", exists=True)],
) -> None:
    """
    Show a lightweight diff summary between two binaries.
    """
    diff_analyzer_cls = _load_diff_analyzer()
    analyzer = diff_analyzer_cls()
    result = analyzer.compare(original, mutated)
    console.print_json(json.dumps(result.__dict__))
    raise typer.Exit(0)


def _handle_report(options: ReportViewOptions) -> None:
    """Display a previously generated engine report."""
    handle_report_command(
        options.report_file,
        ReportCommandOptions(
            only_pass=options.only_pass,
            only_status=options.only_status,
            only_mismatches=options.only_mismatches,
            summary_only=options.summary_only,
            output=options.output,
            require_results=options.require_results,
            min_severity=options.min_severity,
            only_expected_severity=options.only_expected_severity,
            only_pass_failure=options.only_pass_failure,
            only_degraded=options.only_degraded,
            only_failed_gates=options.only_failed_gates,
            pass_classes=PassClassFilters(
                only_risky_passes=options.only_risky_passes,
                only_structural_risk=options.only_structural_risk,
                only_symbolic_risk=options.only_symbolic_risk,
                only_uncovered_passes=options.only_uncovered_passes,
                only_covered_passes=options.only_covered_passes,
                only_clean_passes=options.only_clean_passes,
            ),
            output_format=options.output_format,
        ),
    )


report = CommandCallback("report", ReportViewOptions, _handle_report)
app.command()(report)


@app.command()
def version() -> None:
    """
    Display version information.
    """
    rprint(f"[bold cyan]r2morph[/bold cyan] version [green]{__version__}[/green]")
    rprint("Metamorphic mutation engine with validation")


@app.command()
def cache(
    clear: bool = typer.Option(False, "--clear", "-c", help="Clear all cached analysis results"),
    stats: bool = typer.Option(False, "--stats", "-s", help="Show cache statistics"),
    path: Annotated[Path | None, typer.Option("--path", "-p", help="Custom cache directory path")] = None,
) -> None:
    """
    Manage the analysis cache.

    Examples:
        r2morph cache --stats          # Show cache statistics
        r2morph cache --clear          # Clear all cached data
        r2morph cache --clear --path /custom/cache  # Clear specific cache directory
    """
    try:
        handle_cache_command(clear=clear, stats=stats, path=path, console=console)
    except SystemExit as exc:
        code = exc.code
        raise typer.Exit(code if isinstance(code, int) else (0 if code is None else 1)) from exc


def main() -> None:
    """Entry point for the CLI."""
    argv = sys.argv[1:]
    if argv and not argv[0].startswith("-") and argv[0] not in KNOWN_COMMANDS:
        parser = argparse.ArgumentParser(prog="r2morph")
        parser.add_argument("input_file")
        parser.add_argument("output_file", nargs="?")
        parser.add_argument("-i", "--input", dest="input_opt")
        parser.add_argument("-o", "--output", dest="output_opt")
        parser.add_argument("-a", "--aggressive", action="store_true")
        parser.add_argument("-f", "--force", action="store_true")
        parser.add_argument("--seed", type=int)
        parser.add_argument("-v", "--verbose", action="store_true")
        parser.add_argument("-d", "--debug", action="store_true")
        args = parser.parse_args(argv)
        input_file = Path(args.input_opt or args.input_file)
        output_file = Path(args.output_opt or args.output_file) if (args.output_opt or args.output_file) else None
        _run_simple_mode(
            SimpleModeRequest(
                input_file=input_file,
                output_file=output_file,
                aggressive=args.aggressive,
                force=args.force,
                seed=args.seed,
                verbose=args.verbose,
                debug=args.debug,
            )
        )
        return
    app()


if __name__ == "__main__":
    main()
