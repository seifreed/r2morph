"""
Command-line interface for r2morph.

Primary product flow:
    r2morph input.bin [output.bin]
    r2morph mutate input.bin -o output.bin --report report.json
"""

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from r2morph import __version__
from r2morph.core.config import EngineConfig
from r2morph.core.engine import MorphEngine
from r2morph.core.support import PRODUCT_SUPPORT, is_experimental_mutation, is_stable_mutation
from r2morph.utils.logging import setup_logging
from r2morph.validation import BinaryValidator
from r2morph.validation.validator import RuntimeComparisonConfig

from r2morph.reporting.report_helpers import (
    _attach_gate_evaluation,
    _emit_report_payload,
    _enforce_report_requirements,
    _expected_severity_rank_from_failure,
    _filter_failed_gates_view,
    _finalize_report_output,
    _gate_failure_result_count,
    _has_structural_risk,
    _has_symbolic_risk,
    _is_clean_pass,
    _is_covered_pass,
    _is_risky_pass,
    _is_uncovered_pass,
    _normalized_pass_map,
    _pass_names_from_triage_rows,
    _pass_severity_requirements_met,
    _report_view_has_results,
    _resolve_general_report_views,
    _resolve_summary_pass_sources,
    _select_report_mutations,
    _severity_threshold_met,
    _sort_pass_evidence,
    _summarize_symbolic_view_from_mutations,
    _summary_first,
    _visible_rows,
    SEVERITY_ORDER as _HELPERS_SEVERITY_ORDER,
)
from r2morph.reporting.report_rendering import (
    _render_degradation_sections,
    _render_gate_sections,
    _render_only_mismatches_sections,
    _render_only_pass_sections,
    _render_pass_capabilities,
    _render_pass_validation_context,
    _render_pass_validation_contexts,
    _render_report_filter_messages,
    _render_symbolic_sections,
)
from r2morph.reporting.report_helpers import _resolve_general_filtered_passes
from r2morph.reporting.report_resolver import (
    _resolve_failed_gates_view,
    _resolve_general_report_flow_state,
    _resolve_general_report_state,
    _resolve_general_symbolic_state,
    _resolve_mismatch_severity_rows,
    _resolve_mismatch_view,
    _resolve_only_mismatches_state,
    _resolve_only_pass_view,
    _resolve_pass_filter_sets,
    _resolve_report_gate_state,
)
from r2morph.reporting.filtered_summary_builder import (
    _build_base_filtered_summary,
    _build_filtered_summary_degradation_sections,
    _build_filtered_summary_gate_sections,
    _build_filtered_summary_risk_coverage_sections,
    _build_general_filtered_summary,
    _build_general_report_payload,
    _build_only_mismatches_filtered_summary,
    _build_only_mismatches_payload,
    _build_report_dispatch_state,
    _build_report_filters,
    _populate_filtered_summary_discarded_sections,
    _populate_filtered_summary_pass_sections,
    _populate_filtered_summary_symbolic_sections,
)
from r2morph.reporting.report_orchestrator import (
    _dispatch_report_flow,
    _dispatch_report_flow_ctx,
    _execute_general_report_flow,
    _execute_only_mismatches_report_flow,
    _render_general_flow_sections,
    _render_general_only_pass_sections,
    _render_general_report_sections,
)

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

SUPPORTED_MUTATIONS = set(PRODUCT_SUPPORT.stable_mutations)
EXPERIMENTAL_MUTATIONS = set(PRODUCT_SUPPORT.experimental_mutations)
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

SEVERITY_ORDER = {
    "mismatch": 0,
    "without-coverage": 1,
    "bounded-only": 2,
    "clean": 3,
    "not-requested": 4,
}


def _build_config(aggressive: bool, force: bool) -> EngineConfig:
    config = EngineConfig.create_aggressive() if aggressive else EngineConfig.create_default()
    if force:
        config.force_different = True
        config.nop.force_different = True
        config.substitution.force_different = True
        config.register.force_different = True
        config.expansion.force_different = True
        config.block.force_different = True
    return config


def _mutation_config(section: object, seed: int | None, offset: int) -> dict[str, object]:
    cfg = section.to_dict()
    if seed is not None:
        cfg["seed"] = seed + offset
    return cfg


def _warn_experimental_mutations(mutations: list[str]) -> None:
    if not mutations:
        return
    console.print(f"[yellow]Experimental mutations selected:[/yellow] {', '.join(mutations)}")
    console.print("[yellow]These passes are outside the stable core and validation coverage is best-effort.[/yellow]")


def _warn_experimental_validation_mode(validation_mode: str) -> None:
    if validation_mode != "symbolic":
        return
    console.print("[yellow]Experimental validation mode selected:[/yellow] symbolic")
    console.print(
        "[yellow]This mode performs bounded symbolic prechecks and structural fallback; it does not prove general semantic equivalence.[/yellow]"
    )


def _build_runtime_validator(
    *,
    timeout: int,
    corpus: Path | None = None,
    compare_files: bool = False,
    normalize_whitespace: bool = False,
) -> BinaryValidator:
    """Build a runtime validator from CLI options."""
    validator = BinaryValidator(
        timeout=timeout,
        comparison=RuntimeComparisonConfig(
            compare_files=compare_files,
            normalize_whitespace=normalize_whitespace,
        ),
    )
    if corpus is not None:
        with open(corpus, "r", encoding="utf-8") as handle:
            validator.load_test_cases(json.load(handle))
    return validator


def _load_binary_analyzer():
    """Lazy import for analysis-only flows outside the stable mutate/report path."""
    from r2morph.analysis.analyzer import BinaryAnalyzer

    return BinaryAnalyzer


def _load_diff_analyzer():
    """Lazy import for diff-only flows outside the stable mutate/report hot path."""
    from r2morph.analysis.diff_analyzer import DiffAnalyzer

    return DiffAnalyzer


def _load_mutation_pass_types() -> dict[str, type]:
    """Lazy import mutation passes so stable report/validate flows avoid extra imports."""
    from r2morph.mutations import (
        BlockReorderingPass,
        InstructionExpansionPass,
        InstructionSubstitutionPass,
        NopInsertionPass,
        RegisterSubstitutionPass,
    )

    return {
        "nop": NopInsertionPass,
        "substitute": InstructionSubstitutionPass,
        "register": RegisterSubstitutionPass,
        "expand": InstructionExpansionPass,
        "block": BlockReorderingPass,
    }


def _resolve_min_severity(min_severity: str | None) -> tuple[str | None, int | None]:
    """Validate and normalize a minimum severity option."""
    if min_severity is None:
        return None, None
    if min_severity not in SEVERITY_ORDER:
        console.print(f"[bold red]Error:[/bold red] Invalid --min-severity: {min_severity}")
        raise typer.Exit(2)
    return min_severity, SEVERITY_ORDER[min_severity]


def _resolve_report_context(
    *,
    payload: dict[str, Any],
    only_pass: str | None,
    only_pass_failure: str | None,
    only_expected_severity: str | None,
) -> dict[str, Any]:
    """Thin CLI wrapper: resolves pass aliases then delegates to reporting layer."""
    from r2morph.reporting.report_resolver import _resolve_report_context as _resolve_ctx

    return _resolve_ctx(
        payload=payload,
        resolved_only_pass=_resolve_report_pass_filter(only_pass),
        resolved_only_pass_failure=_resolve_report_pass_filter(only_pass_failure),
        only_expected_severity=only_expected_severity,
    )


def _resolve_pass_severity_requirements(
    requirements: list[str] | None,
    *,
    alias_map: dict[str, str] | None = None,
) -> list[tuple[str, str, int]]:
    """Parse repeated PassName=severity requirements for mutate gating."""
    resolved: list[tuple[str, str, int]] = []
    aliases = {key.strip(): value for key, value in (alias_map or {}).items()}
    valid_pass_names = set(aliases.values())
    for item in requirements or []:
        if "=" not in item:
            console.print(
                f"[bold red]Error:[/bold red] Invalid --require-pass-severity: {item}. Expected PassName=severity"
            )
            raise typer.Exit(2)
        pass_name, severity = item.split("=", 1)
        pass_name = pass_name.strip()
        severity = severity.strip()
        pass_name = aliases.get(pass_name, pass_name)
        if not pass_name or severity not in SEVERITY_ORDER or (valid_pass_names and pass_name not in valid_pass_names):
            console.print(
                "[bold red]Error:[/bold red] "
                f"Invalid --require-pass-severity: {item}. "
                "Expected PassName=severity with severity in "
                "mismatch, without-coverage, bounded-only, clean, not-requested"
            )
            raise typer.Exit(2)
        resolved.append((pass_name, severity, SEVERITY_ORDER[severity]))
    return resolved


def _add_mutations(
    engine: MorphEngine,
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None = None,
) -> None:
    for _mutation_name, mutation_pass in _selected_mutation_passes(
        mutations,
        config,
        seed=seed,
    ):
        engine.add_mutation(mutation_pass)


def _selected_mutation_passes(
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None = None,
) -> list[tuple[str, object]]:
    """Build pass instances for the selected mutation names."""
    pass_types = _load_mutation_pass_types()
    selected: list[tuple[str, object]] = []
    offset = 0
    if "nop" in mutations:
        selected.append(("nop", pass_types["nop"](config=_mutation_config(config.nop, seed, offset))))
        offset += 1
    if "substitute" in mutations:
        selected.append(
            (
                "substitute",
                pass_types["substitute"](config=_mutation_config(config.substitution, seed, offset)),
            )
        )
        offset += 1
    if "register" in mutations:
        selected.append(
            (
                "register",
                pass_types["register"](config=_mutation_config(config.register, seed, offset)),
            )
        )
        offset += 1
    if "expand" in mutations:
        selected.append(
            (
                "expand",
                pass_types["expand"](config=_mutation_config(config.expansion, seed, offset)),
            )
        )
        offset += 1
    if "block" in mutations:
        selected.append(("block", pass_types["block"](config=_mutation_config(config.block, seed, offset))))
    return selected


def _mutation_pass_alias_map(
    config: EngineConfig,
    *,
    seed: int | None = None,
) -> dict[str, str]:
    """Build aliases from short mutation names to concrete pass names."""
    aliases: dict[str, str] = {}
    all_mutations = list(SUPPORTED_MUTATIONS | EXPERIMENTAL_MUTATIONS)
    for mutation_name, mutation_pass in _selected_mutation_passes(
        all_mutations,
        config,
        seed=seed,
    ):
        aliases[mutation_name] = mutation_pass.name
        aliases[mutation_pass.name] = mutation_pass.name
    return aliases


def _resolve_report_pass_filter(pass_name: str | None) -> str | None:
    """Resolve report-side pass filters using the product alias map."""
    if pass_name is None:
        return None
    alias_map = _mutation_pass_alias_map(_build_config(False, False), seed=None)
    return alias_map.get(pass_name.strip(), pass_name.strip())


def _limited_symbolic_passes(
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None,
) -> list[dict[str, str]]:
    """Return passes that declare symbolic support as limited."""
    limited = []
    for mutation_name, mutation_pass in _selected_mutation_passes(mutations, config, seed=seed):
        symbolic_support = mutation_pass.get_support().validator_capabilities.get("symbolic", {})
        if symbolic_support.get("recommended") is False:
            limited.append(
                {
                    "mutation": mutation_name,
                    "pass_name": mutation_pass.name,
                    "confidence": str(symbolic_support.get("confidence", "unknown")),
                }
            )
    return limited


def _warn_or_block_limited_symbolic(
    mutations: list[str],
    config: EngineConfig,
    *,
    seed: int | None,
    allow_limited_symbolic: bool,
) -> None:
    """Block symbolic mode for passes that declare limited symbolic support unless explicitly allowed."""
    limited = []
    for mutation_name, mutation_pass in _selected_mutation_passes(mutations, config, seed=seed):
        symbolic_support = mutation_pass.get_support().validator_capabilities.get("symbolic", {})
        if symbolic_support.get("recommended") is False:
            limited.append(
                {
                    "mutation": mutation_name,
                    "pass_name": mutation_pass.name,
                    "confidence": symbolic_support.get("confidence", "unknown"),
                }
            )
    if not limited:
        return

    names = ", ".join(item["pass_name"] for item in limited)
    if not allow_limited_symbolic:
        console.print(f"[bold red]Error:[/bold red] symbolic validation is marked limited for: {names}")
        console.print("[yellow]Use structural/runtime, or pass --allow-limited-symbolic to continue anyway.[/yellow]")
        raise typer.Exit(2)

    console.print(f"[yellow]Limited symbolic coverage explicitly allowed for:[/yellow] {names}")
    for item in limited:
        console.print(f"[yellow]- {item['pass_name']}: symbolic confidence={item['confidence']}[/yellow]")


def _resolve_validation_mode(
    *,
    requested_mode: str,
    mutations: list[str],
    config: EngineConfig,
    seed: int | None,
    allow_limited_symbolic: bool,
    limited_symbolic_policy: str,
) -> tuple[str, dict[str, object] | None]:
    """Resolve requested vs effective validation mode for limited symbolic passes."""
    if requested_mode != "symbolic":
        return requested_mode, None

    limited = _limited_symbolic_passes(mutations, config, seed=seed)
    if not limited:
        return requested_mode, None

    if allow_limited_symbolic:
        names = ", ".join(item["pass_name"] for item in limited)
        console.print(f"[yellow]Limited symbolic coverage explicitly allowed for:[/yellow] {names}")
        for item in limited:
            console.print(f"[yellow]- {item['pass_name']}: symbolic confidence={item['confidence']}[/yellow]")
        return requested_mode, {
            "requested_mode": requested_mode,
            "effective_mode": requested_mode,
            "policy": "allow",
            "reason": "explicit-override",
            "limited_passes": limited,
        }

    if limited_symbolic_policy == "degrade-runtime":
        names = ", ".join(item["pass_name"] for item in limited)
        console.print(f"[yellow]Limited symbolic support detected for:[/yellow] {names}")
        console.print("[yellow]Degrading validation mode from symbolic to runtime.[/yellow]")
        return "runtime", {
            "requested_mode": requested_mode,
            "effective_mode": "runtime",
            "policy": limited_symbolic_policy,
            "reason": "limited-symbolic-support",
            "limited_passes": limited,
        }

    if limited_symbolic_policy == "degrade-structural":
        names = ", ".join(item["pass_name"] for item in limited)
        console.print(f"[yellow]Limited symbolic support detected for:[/yellow] {names}")
        console.print("[yellow]Degrading validation mode from symbolic to structural.[/yellow]")
        return "structural", {
            "requested_mode": requested_mode,
            "effective_mode": "structural",
            "policy": limited_symbolic_policy,
            "reason": "limited-symbolic-support",
            "limited_passes": limited,
        }

    _warn_or_block_limited_symbolic(
        mutations,
        config,
        seed=seed,
        allow_limited_symbolic=allow_limited_symbolic,
    )
    return requested_mode, None


def _print_mutation_summary(result: dict[str, object], output_path: Path | None = None) -> None:
    table = Table(title="Mutation Engine Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    requested_mode = result.get("requested_validation_mode", result.get("validation_mode", "off"))
    effective_mode = result.get("validation_mode", "off")
    table.add_row("Requested Validation", str(requested_mode))
    table.add_row("Effective Validation", str(effective_mode))
    table.add_row("Total Mutations", str(result.get("total_mutations", 0)))
    table.add_row("Passes Run", str(result.get("passes_run", 0)))
    table.add_row("Rolled Back Passes", str(result.get("rolled_back_passes", 0)))
    table.add_row("Discarded Mutations", str(result.get("discarded_mutations", 0)))
    table.add_row(
        "Validation Passed",
        "yes" if result.get("validation", {}).get("all_passed", False) else "no",
    )
    total_issues = result.get("validation", {}).get("total_issues", 0)
    table.add_row("Validation Issues", str(total_issues))
    for pass_name, pass_result in result.get("pass_results", {}).items():
        if "error" in pass_result:
            table.add_row(pass_name, f"[red]Error: {pass_result['error']}[/red]")
            continue
        rolled_back = ""
        if pass_result.get("rolled_back"):
            reason = pass_result.get("rollback_reason", "rollback")
            rolled_back = f" (rolled back: {reason})"
        table.add_row(
            pass_name,
            f"{pass_result.get('mutations_applied', 0)} mutations{rolled_back}",
        )

    console.print(table)
    if output_path is not None:
        console.print(f"\n[bold green]✓[/bold green] Binary saved to: {output_path}")


def _run_simple_mode(
    input_file: Path,
    output_file: Path | None,
    *,
    aggressive: bool,
    force: bool,
    seed: int | None,
    verbose: bool,
    debug: bool,
) -> None:
    setup_logging("DEBUG" if (verbose or debug) else "INFO")

    if output_file is None:
        output_file = input_file.parent / f"{input_file.stem}_morphed{input_file.suffix}"

    mode_str = "[bold red]AGGRESSIVE[/bold red]" if aggressive else "[bold green]STANDARD[/bold green]"
    force_str = " [bold yellow](FORCE)[/bold yellow]" if force else ""
    console.print(f"[bold green]r2morph - Simple Mode ({mode_str}{force_str})[/bold green]")
    console.print(f"Input:  {input_file}")
    console.print(f"Output: {output_file}")
    console.print("Applying stable mutations: [cyan]nop, substitute, register[/cyan]\n")

    with console.status("[bold green]Transforming binary..."):
        with MorphEngine(config={"seed": seed, "requested_mutations": ["nop", "substitute", "register"]}) as engine:
            engine.load_binary(input_file).analyze()
            config = _build_config(aggressive, force)
            _add_mutations(engine, ["nop", "substitute", "register"], config, seed=seed)

            report_path = output_file.parent / f"{output_file.stem}.report.json"
            result = engine.run(
                validation_mode="structural",
                rollback_policy="skip-invalid-pass",
                report_path=report_path,
                seed=seed,
            )

            engine.save(output_file)

        _print_mutation_summary(result, output_file)
        console.print(f"[cyan]Report:[/cyan] {report_path}")


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
):
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

    input_file = input_opt
    output_file = output_opt
    positional = [arg for arg in ctx.args if not arg.startswith("-")]
    if input_file is None and positional:
        input_file = Path(positional[0])
        if len(positional) > 1:
            output_file = Path(positional[1])

    if input_file is None:
        console.print("[yellow]No input file provided.[/yellow]")
        console.print("\nUsage:")
        console.print("  Simple:   [cyan]r2morph input.exe [output.exe][/cyan]")
        console.print("  Alternative:   [cyan]r2morph -i input.exe -o output.exe[/cyan]")
        console.print("  Aggressive: [cyan]r2morph -i input.exe -o output.exe --aggressive[/cyan]")
        console.print("\nRun [cyan]r2morph --help[/cyan] for more options")
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
):
    """
    Analyze a binary and display statistics.
    """
    setup_logging("DEBUG" if verbose else "INFO")

    with console.status("[bold green]Analyzing binary..."):
        try:
            BinaryAnalyzer = _load_binary_analyzer()
            with MorphEngine() as engine:
                engine.load_binary(binary).analyze()
                analyzer = BinaryAnalyzer(engine.binary)
                stats = analyzer.get_statistics()

            table = Table(title=f"Binary Analysis: {binary.name}")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            arch = stats["architecture"]
            table.add_row("Architecture", f"{arch['arch']} ({arch['bits']}-bit)")
            table.add_row("Format", arch["format"])
            table.add_row("Endian", arch["endian"])
            table.add_row("Total Functions", str(stats["total_functions"]))
            table.add_row("Total Instructions", str(stats["total_instructions"]))
            table.add_row("Total Basic Blocks", str(stats["total_basic_blocks"]))
            table.add_row("Total Code Size", f"{stats['total_code_size']} bytes")
            table.add_row("Avg Function Size", f"{stats['avg_function_size']:.2f} bytes")
            table.add_row(
                "Avg Instructions/Function",
                f"{stats['avg_instructions_per_function']:.2f}",
            )

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
):
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
        EnhancedAnalysisOrchestrator,
        AnalysisOptions,
        check_enhanced_dependencies,
    )

    if not check_enhanced_dependencies():
        console.print("[bold red]Error:[/bold red] Enhanced analysis requires additional dependencies.")
        console.print("Install with: [cyan]pip install 'r2morph[enhanced]'[/cyan]")
        raise typer.Exit(1)

    with console.status("[bold green]Analyzing obfuscated binary..."):
        try:
            # Configure analysis options
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
):
    """
    List functions in a binary.
    """
    setup_logging("DEBUG" if verbose else "INFO")

    with console.status("[bold green]Loading binary..."):
        try:
            BinaryAnalyzer = _load_binary_analyzer()
            with MorphEngine() as engine:
                engine.load_binary(binary).analyze()
                analyzer = BinaryAnalyzer(engine.binary)
                funcs = analyzer.get_functions_list()

            table = Table(title=f"Functions in {binary.name}")
            table.add_column("Address", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Size", style="yellow")
            table.add_column("Instructions", style="magenta")

            for func in funcs[:limit]:
                table.add_row(
                    f"0x{func.address:x}",
                    func.name,
                    str(func.size),
                    str(func.get_instructions_count()),
                )

            console.print(table)

            if len(funcs) > limit:
                console.print(
                    f"\n[yellow]Showing {limit} of {len(funcs)} functions. Use --limit to show more.[/yellow]"
                )

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
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
):
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

    unknown = [m for m in mutations if m not in SUPPORTED_MUTATIONS | EXPERIMENTAL_MUTATIONS]
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
    )


def _run_morph_workflow(
    *,
    binary: Path,
    output: Path,
    mutations: list[str],
    aggressive: bool,
    force: bool,
    validation_mode: str,
    allow_limited_symbolic: bool,
    limited_symbolic_policy: str,
    rollback_policy: str,
    report: Path | None,
    runtime_corpus: Path | None,
    runtime_compare_files: bool,
    runtime_normalize_whitespace: bool,
    runtime_timeout: int,
    min_severity: str | None,
    require_pass_severity: list[str] | None,
    seed: int | None,
) -> None:
    """Execute the mutation pipeline, validate, and write results.

    Separated from the morph() CLI command to keep typer declarations
    apart from business logic.
    """
    mode_str = "[bold red]AGGRESSIVE[/bold red]" if aggressive else "[bold green]STANDARD[/bold green]"
    console.print(f"[bold green]Starting mutation pipeline ({mode_str})[/bold green]")
    console.print(f"Input:  {binary}")
    console.print(f"Output: {output}")
    console.print(f"Mutations: {', '.join(mutations)}\n")

    experimental = [m for m in mutations if is_experimental_mutation(m)]
    _warn_experimental_mutations(experimental)
    _warn_experimental_validation_mode(validation_mode)
    _, min_severity_rank = _resolve_min_severity(min_severity)
    config = _build_config(aggressive, force)
    pass_severity_requirements = _resolve_pass_severity_requirements(
        require_pass_severity,
        alias_map=_mutation_pass_alias_map(config, seed=seed),
    )
    effective_validation_mode, validation_policy = _resolve_validation_mode(
        requested_mode=validation_mode,
        mutations=mutations,
        config=config,
        seed=seed,
        allow_limited_symbolic=allow_limited_symbolic,
        limited_symbolic_policy=limited_symbolic_policy,
    )

    with console.status("[bold green]Transforming binary..."):
        try:
            with MorphEngine(
                config={
                    "seed": seed,
                    "requested_mutations": list(mutations),
                    "experimental_mutations": experimental,
                    "requested_validation_mode": validation_mode,
                    "effective_validation_mode": effective_validation_mode,
                    "validation_policy": validation_policy,
                }
            ) as engine:
                engine.load_binary(binary).analyze()
                _add_mutations(engine, mutations, config, seed=seed)

                runtime_validator = None
                if effective_validation_mode == "runtime":
                    runtime_validator = _build_runtime_validator(
                        timeout=runtime_timeout,
                        corpus=runtime_corpus,
                        compare_files=runtime_compare_files,
                        normalize_whitespace=runtime_normalize_whitespace,
                    )

                report_path = report or output.parent / f"{output.stem}.report.json"
                result = engine.run(
                    validation_mode=effective_validation_mode,
                    rollback_policy=rollback_policy,
                    checkpoint_per_mutation=rollback_policy == "skip-invalid-mutation",
                    runtime_validator=runtime_validator,
                    runtime_validate_per_pass=effective_validation_mode == "runtime",
                    report_path=report_path,
                    seed=seed,
                )
                engine.save(output)

            _print_mutation_summary(result, output)
            console.print(f"[cyan]Report:[/cyan] {report_path}")
            report_payload = engine.build_report(result)
            _evaluate_and_write_gates(
                report_payload=report_payload,
                report_path=report_path,
                min_severity=min_severity,
                min_severity_rank=min_severity_rank,
                pass_severity_requirements=pass_severity_requirements,
            )
        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)


def _evaluate_and_write_gates(
    *,
    report_payload: dict[str, Any],
    report_path: Path | None,
    min_severity: str | None,
    min_severity_rank: int | None,
    pass_severity_requirements: list[tuple[str, str, int]] | None,
) -> None:
    """Evaluate severity gates, write report, and exit on failure."""
    severity_rows = list(report_payload.get("summary", {}).get("symbolic_severity_by_pass", []))
    min_severity_passed = _severity_threshold_met(severity_rows, min_severity_rank)
    pass_requirements_ok = True
    pass_requirement_failures: list[str] = []
    if pass_severity_requirements:
        pass_requirements_ok, pass_requirement_failures = _pass_severity_requirements_met(
            severity_rows, pass_severity_requirements,
        )
    report_payload = _attach_gate_evaluation(
        report_payload,
        min_severity=min_severity,
        min_severity_passed=min_severity_passed,
        require_pass_severity=pass_severity_requirements,
        require_pass_severity_passed=pass_requirements_ok,
        require_pass_severity_failures=pass_requirement_failures,
    )
    if report_path is not None:
        report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
    if min_severity is not None and not min_severity_passed:
        console.print(f"[bold yellow]Severity gate failed:[/bold yellow] min_severity={min_severity}")
        raise typer.Exit(1)
    if min_severity is not None:
        console.print(f"[cyan]Severity gate passed:[/cyan] min_severity={min_severity}")
    if pass_severity_requirements and not pass_requirements_ok:
        console.print("[bold yellow]Pass severity gate failed:[/bold yellow] " + ", ".join(pass_requirement_failures))
        raise typer.Exit(1)
    if pass_severity_requirements:
        console.print(
            "[cyan]Pass severity gate passed:[/cyan] "
            + ", ".join(f"{pn}<={s}" for pn, s, _ in pass_severity_requirements)
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
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
):
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
):
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
):
    """
    Show a lightweight diff summary between two binaries.
    """
    DiffAnalyzer = _load_diff_analyzer()
    analyzer = DiffAnalyzer()
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
):
    """
    Display a previously generated engine report.
    """
    if output_format.lower() == "sarif":
        from r2morph.reporting.sarif_formatter import format_as_sarif

    with open(report_file, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    context = _resolve_report_context(
        payload=payload,
        only_pass=only_pass,
        only_pass_failure=only_pass_failure,
        only_expected_severity=only_expected_severity,
    )
    summary = context["summary"]
    resolved_only_pass = context["resolved_only_pass"]
    resolved_only_pass_failure = context["resolved_only_pass_failure"]
    requested_validation_mode = context["requested_validation_mode"]
    effective_validation_mode = context["effective_validation_mode"]
    validation_policy = context["validation_policy"]
    gate_evaluation = context["gate_evaluation"]
    gate_requested = context["gate_requested"]
    gate_results = context["gate_results"]
    gate_failure_summary = context["gate_failure_summary"]
    gate_failure_priority = context["gate_failure_priority"]
    gate_failure_severity_priority = context["gate_failure_severity_priority"]
    failed_gates = context["failed_gates"]
    degraded_validation = context["degraded_validation"]
    degraded_passes = context["degraded_passes"]

    pass_results = payload.get("passes", {})
    general_state = _resolve_general_report_flow_state(
        payload=payload,
        summary=summary,
        pass_results=pass_results,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degraded_validation=degraded_validation,
        degraded_passes=degraded_passes,
        failed_gates=failed_gates,
        validation_policy=validation_policy,
        gate_evaluation=gate_evaluation,
        gate_failure_summary=gate_failure_summary,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
        resolved_only_pass=resolved_only_pass,
        only_status=only_status,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
    )
    _, min_severity_rank = _resolve_min_severity(min_severity)
    dispatch_state = _build_report_dispatch_state(
        context=context,
        general_state=general_state,
        payload=payload,
        pass_results=pass_results,
        only_pass=only_pass,
        only_pass_failure=only_pass_failure,
        only_status=only_status,
        only_degraded=only_degraded,
        only_failed_gates=only_failed_gates,
        only_risky_passes=only_risky_passes,
        only_structural_risk=only_structural_risk,
        only_symbolic_risk=only_symbolic_risk,
        only_uncovered_passes=only_uncovered_passes,
        only_covered_passes=only_covered_passes,
        only_clean_passes=only_clean_passes,
        output=output,
        summary_only=summary_only,
        require_results=require_results,
        min_severity=min_severity,
        min_severity_rank=min_severity_rank,
        only_expected_severity=only_expected_severity,
        only_mismatches=only_mismatches,
    )
    if output_format.lower() == "sarif":
        from r2morph.reporting.sarif_formatter import format_as_sarif

        sarif_report = format_as_sarif(payload)
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(sarif_report)
            rprint(f"[green]SARIF report written to[/green] {output}")
        else:
            print(sarif_report)
        return

    _dispatch_report_flow(**dispatch_state)


@app.command()
def version():
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
):
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
        console.print(f"[cyan]Cache Statistics:[/cyan]")
        console.print(f"  Hits: {statistics.hits}")
        console.print(f"  Misses: {statistics.misses}")
        console.print(f"  Hit Rate: {statistics.hit_rate:.2%}")
        console.print(f"  Entries: {statistics.entry_count}")
        console.print(f"  Size: {statistics.total_size_bytes / (1024 * 1024):.2f} MB")
        if statistics.oldest_entry:
            console.print(f"  Oldest Entry: {statistics.oldest_entry.isoformat()}")
        if statistics.newest_entry:
            console.print(f"  Newest Entry: {statistics.newest_entry.isoformat()}")
        return

    if clear:
        cleared = cache_instance.clear()
        console.print(f"[green]Cleared {cleared} cache entries[/green]")
        return

    console.print("[yellow]Specify --clear or --stats[/yellow]")
    raise typer.Exit(1)


def main():
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
