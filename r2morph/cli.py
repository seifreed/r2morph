"""
Command-line interface for r2morph.

Primary product flow:
    r2morph input.bin [output.bin]
    r2morph mutate input.bin -o output.bin --report report.json
"""

import argparse
import json
import sys
from pathlib import Path

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from r2morph import __version__
from r2morph.cli_cache_output import (
    build_cache_cleared_message,
    build_cache_statistics_lines,
    build_cache_usage_hint,
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
from r2morph.cli_workflows import _build_runtime_validator, _run_morph_workflow, _run_simple_mode
from r2morph.core.engine import MorphEngine
from r2morph.core.support import PRODUCT_SUPPORT
from r2morph.reporting.cli_commands import handle_report_command
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


def _load_binary_analyzer() -> type:
    """Lazy import for analysis-only flows outside the stable mutate/report path."""
    from r2morph.analysis.analyzer import BinaryAnalyzer

    return BinaryAnalyzer


def _load_diff_analyzer() -> type:
    """Lazy import for diff-only flows outside the stable mutate/report hot path."""
    from r2morph.analysis.diff_analyzer import DiffAnalyzer

    return DiffAnalyzer


@app.callback()
def main_callback(
    ctx: typer.Context,
    input_opt: Path | None = typer.Option(None, "--input", "-i", help="Input binary file (alternative style)"),
    output_opt: Path | None = typer.Option(None, "--output", "-o", help="Output binary file (alternative style)"),
    aggressive: bool = typer.Option(
        False, "--aggressive", "-a", help="Aggressive mode: more mutations, higher probability"
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Force mutations to be different from original"),
    seed: int | None = typer.Option(None, "--seed", help="Deterministic seed for stable mutation selection"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug output"),
) -> None:
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
    if ctx.invoked_subcommand is not None:
        return

    input_file, output_file = resolve_main_cli_paths(
        input_opt,
        output_opt,
        [arg for arg in ctx.args if not arg.startswith("-")],
    )

    if input_file is None:
        for line in build_missing_input_help_lines():
            console.print(line)
        raise typer.Exit(0)

    try:
        _run_simple_mode(
            input_file,
            output_file,
            aggressive=aggressive,
            force=force,
            seed=seed,
            verbose=verbose,
            debug=debug,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        if verbose or debug:
            import traceback

            console.print(traceback.format_exc())
        raise typer.Exit(1)


@app.command()
def analyze(
    binary: Path = typer.Argument(..., help="Path to binary file", exists=True),
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
            raise typer.Exit(1)


@experimental_app.command("analyze-enhanced")
def analyze_enhanced(
    binary: Path = typer.Argument(..., help="Path to binary file", exists=True),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    detect_only: bool = typer.Option(False, "--detect-only", help="Only run obfuscation detection"),
    symbolic: bool = typer.Option(False, "--symbolic", help="Enable symbolic execution analysis"),
    dynamic: bool = typer.Option(False, "--dynamic", help="Enable dynamic instrumentation"),
    devirt: bool = typer.Option(False, "--devirt", help="Enable devirtualization analysis"),
    iterative: bool = typer.Option(False, "--iterative", help="Enable iterative simplification"),
    rewrite: bool = typer.Option(False, "--rewrite", help="Enable binary rewriting"),
    bypass: bool = typer.Option(False, "--bypass", help="Enable anti-analysis bypass"),
    output: Path = typer.Option(None, "--output", "-o", help="Output directory for results"),
) -> None:
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
    setup_logging("DEBUG" if verbose else "INFO")

    from r2morph.analysis.enhanced_analyzer import (
        AnalysisOptions,
        EnhancedAnalysisOrchestrator,
        check_enhanced_dependencies,
    )

    if not check_enhanced_dependencies():
        console.print("[bold red]Error:[/bold red] Enhanced analysis requires additional dependencies.")
        console.print("Install with: [cyan]pip install 'r2morph[enhanced]'[/cyan]")
        raise typer.Exit(1)

    with console.status("[bold green]Analyzing obfuscated binary..."):
        try:
            options = AnalysisOptions(
                verbose=verbose,
                detect_only=detect_only,
                symbolic=symbolic,
                dynamic=dynamic,
                devirt=devirt,
                iterative=iterative,
                rewrite=rewrite,
                bypass=bypass,
            )

            orchestrator = EnhancedAnalysisOrchestrator(
                binary_path=binary,
                output_dir=output,
                console=console,
            )

            orchestrator.analyze(options)

        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            if verbose:
                import traceback

                console.print(traceback.format_exc())
            raise typer.Exit(1)


@app.command()
def functions(
    binary: Path = typer.Argument(..., help="Path to binary file", exists=True),
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
            raise typer.Exit(1)


@app.command()
def morph(
    binary: Path = typer.Argument(..., help="Path to binary file", exists=True),
    output: Path = typer.Option(None, "--output", "-o", help="Output path for morphed binary"),
    mutations: list[str] = typer.Option(
        ["nop", "substitute", "register"],
        "--mutation",
        "-m",
        help="Mutations to apply (stable: nop, substitute, register; experimental: expand, block)",
    ),
    aggressive: bool = typer.Option(False, "--aggressive", "-a", help="Aggressive mode: more mutations"),
    force: bool = typer.Option(False, "--force", "-f", help="Force mutations to be different from original"),
    validation_mode: str = typer.Option(
        "structural",
        "--validation-mode",
        help="Validation mode: structural, runtime, symbolic, off",
    ),
    allow_limited_symbolic: bool = typer.Option(
        False,
        "--allow-limited-symbolic",
        help="Allow symbolic mode for passes that declare limited symbolic support",
    ),
    limited_symbolic_policy: str = typer.Option(
        "block",
        "--limited-symbolic-policy",
        help="How to handle limited symbolic passes: block, degrade-runtime, degrade-structural",
    ),
    rollback_policy: str = typer.Option(
        "skip-invalid-pass",
        "--rollback-policy",
        help="Rollback policy: fail-fast, skip-invalid-pass, skip-invalid-mutation",
    ),
    report: Path | None = typer.Option(
        None,
        "--report",
        help="Write a machine-readable JSON report",
    ),
    runtime_corpus: Path | None = typer.Option(
        None,
        "--runtime-corpus",
        help="Optional JSON corpus for runtime validation during mutate",
    ),
    runtime_compare_files: bool = typer.Option(
        False,
        "--runtime-compare-files",
        help="Compare monitored files during runtime validation",
    ),
    runtime_normalize_whitespace: bool = typer.Option(
        False,
        "--runtime-normalize-whitespace",
        help="Ignore trailing whitespace differences during runtime validation",
    ),
    runtime_timeout: int = typer.Option(
        10,
        "--runtime-timeout",
        help="Timeout per runtime validation test case in seconds",
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Fail with code 1 unless the final report contains at least one pass at or above: mismatch, without-coverage, bounded-only, clean, not-requested",
    ),
    require_pass_severity: list[str] = typer.Option(
        None,
        "--require-pass-severity",
        help="Require a specific pass severity in the final report, e.g. InstructionSubstitution=bounded-only",
    ),
    seed: int | None = typer.Option(None, "--seed", help="Deterministic seed for mutation selection"),
    cache: bool = typer.Option(
        False,
        "--cache",
        help="Enable analysis caching for faster repeated runs",
    ),
    clear_cache: bool = typer.Option(
        False,
        "--clear-cache",
        help="Clear the analysis cache before running",
    ),
    report_format: str = typer.Option("json", "--format", help="Report format: json (default) or sarif"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
) -> None:
    """
    Apply tracked mutations to a binary and validate the result.

    Examples:
        r2morph mutate binary.exe -o output.exe
        r2morph mutate binary.exe -m nop -m substitute --report report.json
        r2morph mutate binary.exe --cache  # Enable caching for faster repeated runs
    """
    setup_logging("DEBUG" if verbose else "INFO")

    if not output:
        output = binary.parent / f"{binary.stem}_morphed{binary.suffix}"

    if clear_cache:
        from r2morph.core.analysis_cache import AnalysisCache

        cleared = AnalysisCache().clear()
        console.print(f"[cyan]Cleared {cleared} cache entries[/cyan]")

    unknown = [m for m in mutations if m not in set(PRODUCT_SUPPORT.stable_mutations) | set(PRODUCT_SUPPORT.experimental_mutations)]
    if unknown:
        console.print(f"[bold red]Error:[/bold red] Unknown mutations: {', '.join(unknown)}")
        raise typer.Exit(2)

    _run_morph_workflow(
        binary=binary,
        output=output,
        mutations=mutations,
        aggressive=aggressive,
        force=force,
        validation_mode=validation_mode,
        allow_limited_symbolic=allow_limited_symbolic,
        limited_symbolic_policy=limited_symbolic_policy,
        rollback_policy=rollback_policy,
        report=report,
        runtime_corpus=runtime_corpus,
        runtime_compare_files=runtime_compare_files,
        runtime_normalize_whitespace=runtime_normalize_whitespace,
        runtime_timeout=runtime_timeout,
        min_severity=min_severity,
        require_pass_severity=require_pass_severity,
        seed=seed,
        report_format=report_format,
    )


@app.command(name="mutate")
def mutate(
    binary: Path = typer.Argument(..., help="Path to binary file", exists=True),
    output: Path = typer.Option(None, "--output", "-o", help="Output path for morphed binary"),
    mutations: list[str] = typer.Option(
        ["nop", "substitute", "register"],
        "--mutation",
        "-m",
        help="Mutations to apply (stable: nop, substitute, register; experimental: expand, block)",
    ),
    aggressive: bool = typer.Option(False, "--aggressive", "-a", help="Aggressive mode: more mutations"),
    force: bool = typer.Option(False, "--force", "-f", help="Force mutations to be different from original"),
    validation_mode: str = typer.Option(
        "structural",
        "--validation-mode",
        help="Validation mode: structural, runtime, symbolic, off",
    ),
    allow_limited_symbolic: bool = typer.Option(
        False,
        "--allow-limited-symbolic",
        help="Allow symbolic mode for passes that declare limited symbolic support",
    ),
    limited_symbolic_policy: str = typer.Option(
        "block",
        "--limited-symbolic-policy",
        help="How to handle limited symbolic passes: block, degrade-runtime, degrade-structural",
    ),
    rollback_policy: str = typer.Option(
        "skip-invalid-pass",
        "--rollback-policy",
        help="Rollback policy: fail-fast, skip-invalid-pass, skip-invalid-mutation",
    ),
    report: Path | None = typer.Option(
        None,
        "--report",
        help="Write a machine-readable JSON report",
    ),
    runtime_corpus: Path | None = typer.Option(
        None,
        "--runtime-corpus",
        help="Optional JSON corpus for runtime validation during mutate",
    ),
    runtime_compare_files: bool = typer.Option(
        False,
        "--runtime-compare-files",
        help="Compare monitored files during runtime validation",
    ),
    runtime_normalize_whitespace: bool = typer.Option(
        False,
        "--runtime-normalize-whitespace",
        help="Ignore trailing whitespace differences during runtime validation",
    ),
    runtime_timeout: int = typer.Option(
        10,
        "--runtime-timeout",
        help="Timeout per runtime validation test case in seconds",
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Fail with code 1 unless the final report contains at least one pass at or above: mismatch, without-coverage, bounded-only, clean, not-requested",
    ),
    require_pass_severity: list[str] = typer.Option(
        None,
        "--require-pass-severity",
        help="Require a specific pass severity in the final report, e.g. InstructionSubstitution=bounded-only",
    ),
    seed: int | None = typer.Option(None, "--seed", help="Deterministic seed for mutation selection"),
    report_format: str = typer.Option("json", "--format", help="Report format: json (default) or sarif"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
) -> None:
    """Alias for `morph` using the product-oriented command name."""
    return morph(
        binary=binary,
        output=output,
        mutations=mutations,
        aggressive=aggressive,
        force=force,
        validation_mode=validation_mode,
        allow_limited_symbolic=allow_limited_symbolic,
        limited_symbolic_policy=limited_symbolic_policy,
        rollback_policy=rollback_policy,
        report=report,
        runtime_corpus=runtime_corpus,
        runtime_compare_files=runtime_compare_files,
        runtime_normalize_whitespace=runtime_normalize_whitespace,
        runtime_timeout=runtime_timeout,
        min_severity=min_severity,
        require_pass_severity=require_pass_severity,
        seed=seed,
        report_format=report_format,
        verbose=verbose,
    )


@app.command()
def validate(
    original: Path = typer.Argument(..., help="Original binary", exists=True),
    mutated: Path = typer.Argument(..., help="Mutated binary", exists=True),
    corpus: Path | None = typer.Option(
        None,
        "--corpus",
        help="Optional JSON corpus describing runtime test cases (see dataset/runtime_corpus.json)",
    ),
    compare_files: bool = typer.Option(
        False,
        "--compare-files",
        help="Compare monitored output files in addition to stdout/stderr/exitcode",
    ),
    normalize_whitespace: bool = typer.Option(
        False,
        "--normalize-whitespace",
        help="Ignore trailing whitespace differences in stdout/stderr",
    ),
    timeout: int = typer.Option(10, "--timeout", help="Timeout per test case in seconds"),
) -> None:
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
        timeout=timeout,
        corpus=corpus,
        compare_files=compare_files,
        normalize_whitespace=normalize_whitespace,
    )
    result = validator.validate(original, mutated)
    console.print_json(json.dumps(result.to_dict()))
    raise typer.Exit(0 if result.passed else 1)


@app.command()
def diff(
    original: Path = typer.Argument(..., help="Original binary", exists=True),
    mutated: Path = typer.Argument(..., help="Mutated binary", exists=True),
) -> None:
    """
    Show a lightweight diff summary between two binaries.
    """
    diff_analyzer_cls = _load_diff_analyzer()
    analyzer = diff_analyzer_cls()
    result = analyzer.compare(original, mutated)
    console.print_json(json.dumps(result.__dict__))
    raise typer.Exit(0)


@app.command()
def report(
    report_file: Path = typer.Argument(..., help="Report JSON generated by mutate", exists=True),
    only_pass: str | None = typer.Option(
        None,
        "--only-pass",
        help="Show only mutations produced by the specified pass name",
    ),
    only_status: str | None = typer.Option(
        None,
        "--only-status",
        help="Show only mutations with the specified symbolic_status",
    ),
    only_mismatches: bool = typer.Option(
        False,
        "--only-mismatches",
        help="Show only mutations with symbolic observable mismatches",
    ),
    summary_only: bool = typer.Option(
        False,
        "--summary-only",
        help="Show only the textual summary without printing report JSON",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the filtered report JSON to a file",
    ),
    require_results: bool = typer.Option(
        False,
        "--require-results",
        help="Exit with code 1 when the filtered view contains no mutations",
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Require at least one pass with severity: mismatch, without-coverage, bounded-only, clean, not-requested",
    ),
    only_expected_severity: str | None = typer.Option(
        None,
        "--only-expected-severity",
        help="Filter persisted gate failures by expected severity: mismatch, without-coverage, bounded-only, clean, not-requested",
    ),
    only_pass_failure: str | None = typer.Option(
        None,
        "--only-pass-failure",
        help="Filter persisted gate failures to a specific pass name",
    ),
    only_degraded: bool = typer.Option(
        False,
        "--only-degraded",
        help="Show/report only executions where requested and effective validation modes differ",
    ),
    only_failed_gates: bool = typer.Option(
        False,
        "--only-failed-gates",
        help="Show/report only executions where persisted CLI gate evaluation failed",
    ),
    only_risky_passes: bool = typer.Option(
        False,
        "--only-risky-passes",
        help="Show/report only passes with symbolic mismatches, structural issues, or non-clean symbolic severity",
    ),
    only_structural_risk: bool = typer.Option(
        False,
        "--only-structural-risk",
        help="Show/report only passes with structural issues",
    ),
    only_symbolic_risk: bool = typer.Option(
        False,
        "--only-symbolic-risk",
        help="Show/report only passes with symbolic mismatches or non-clean symbolic severity",
    ),
    only_clean_passes: bool = typer.Option(
        False,
        "--only-clean-passes",
        help="Show/report only passes with no structural issues and clean symbolic evidence",
    ),
    only_covered_passes: bool = typer.Option(
        False,
        "--only-covered-passes",
        help="Show/report only clean passes with effective symbolic coverage",
    ),
    only_uncovered_passes: bool = typer.Option(
        False,
        "--only-uncovered-passes",
        help="Show/report only clean passes without effective symbolic coverage",
    ),
    output_format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Output format: json (default) or sarif",
    ),
) -> None:
    """
    Display a previously generated engine report.
    """
    handle_report_command(
        report_file=report_file,
        only_pass=only_pass,
        only_status=only_status,
        only_mismatches=only_mismatches,
        summary_only=summary_only,
        output=output,
        require_results=require_results,
        min_severity=min_severity,
        only_expected_severity=only_expected_severity,
        only_pass_failure=only_pass_failure,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_clean_passes=only_clean_passes,
        only_covered_passes=only_covered_passes,
        only_uncovered_passes=only_uncovered_passes,
        output_format=output_format,
    )


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
    path: Path | None = typer.Option(None, "--path", "-p", help="Custom cache directory path"),
) -> None:
    """
    Manage the analysis cache.

    Examples:
        r2morph cache --stats          # Show cache statistics
        r2morph cache --clear          # Clear all cached data
        r2morph cache --clear --path /custom/cache  # Clear specific cache directory
    """
    from r2morph.core.analysis_cache import AnalysisCache

    cache_dir = path if path else None
    cache_instance = AnalysisCache(cache_dir=cache_dir)

    if stats:
        statistics = cache_instance.get_stats()
        for line in build_cache_statistics_lines(statistics):
            if line == "Cache Statistics:":
                console.print(f"[cyan]{line}[/cyan]")
            else:
                console.print(line)
        return

    if clear:
        cleared = cache_instance.clear()
        console.print(f"[green]{build_cache_cleared_message(cleared)}[/green]")
        return

    console.print(f"[yellow]{build_cache_usage_hint()}[/yellow]")
    raise typer.Exit(1)


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
            input_file,
            output_file,
            aggressive=args.aggressive,
            force=args.force,
            seed=args.seed,
            verbose=args.verbose,
            debug=args.debug,
        )
        return
    app()


if __name__ == "__main__":
    main()
