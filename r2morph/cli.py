"""
Command-line interface for r2morph.

Ultra-simple usage (like r2morph):
    r2morph input.exe [output.exe]

Advanced usage:
    r2morph morph input.exe -o output.exe -m nop -m substitute
"""

from pathlib import Path

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from r2morph import __version__
from r2morph.analysis.analyzer import BinaryAnalyzer
from r2morph.core.config import EngineConfig
from r2morph.core.engine import MorphEngine
from r2morph.mutations import (
    BlockReorderingPass,
    InstructionExpansionPass,
    InstructionSubstitutionPass,
    NopInsertionPass,
    RegisterSubstitutionPass,
)
from r2morph.utils.logging import setup_logging

app = typer.Typer(
    name="r2morph",
    help="A metamorphic binary transformation engine based on r2pipe and radare2",
    add_completion=False,
    invoke_without_command=True,
)
console = Console()


@app.callback()
def main_callback(
    ctx: typer.Context,
    input_file: Path | None = typer.Argument(None, help="Input binary file"),
    output_file: Path | None = typer.Argument(None, help="Output binary file (optional)"),
    input_opt: Path | None = typer.Option(
        None, "--input", "-i", help="Input binary file (alternative style)"
    ),
    output_opt: Path | None = typer.Option(
        None, "--output", "-o", help="Output binary file (alternative style)"
    ),
    aggressive: bool = typer.Option(
        False, "--aggressive", "-a", help="Aggressive mode: more mutations, higher probability"
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Force mutations to be different from original"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug output"),
):
    """
    r2morph - Metamorphic binary transformation engine

    SIMPLE USAGE (like r2morph):
        r2morph input.exe [output.exe]
        r2morph -i input.exe -o output.exe

    This will automatically apply ALL mutations to the binary.

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

    if input_opt:
        input_file = input_opt
    if output_opt:
        output_file = output_opt

    if input_file is None:
        console.print("[yellow]No input file provided.[/yellow]")
        console.print("\nUsage:")
        console.print("  Simple:   [cyan]r2morph input.exe [output.exe][/cyan]")
        console.print("  Alternative:   [cyan]r2morph -i input.exe -o output.exe[/cyan]")
        console.print("  Aggressive: [cyan]r2morph -i input.exe -o output.exe --aggressive[/cyan]")
        console.print("\nRun [cyan]r2morph --help[/cyan] for more options")
        raise typer.Exit(0)

    setup_logging("DEBUG" if (verbose or debug) else "INFO")

    if output_file is None:
        output_file = input_file.parent / f"{input_file.stem}_morphed{input_file.suffix}"

    mode_str = (
        "[bold red]AGGRESSIVE[/bold red]" if aggressive else "[bold green]STANDARD[/bold green]"
    )
    force_str = " [bold yellow](FORCE)[/bold yellow]" if force else ""
    console.print(f"[bold green]r2morph - Simple Mode ({mode_str}{force_str})[/bold green]")
    console.print(f"Input:  {input_file}")
    console.print(f"Output: {output_file}")
    console.print("Applying [cyan]ALL[/cyan] mutations...\n")

    with console.status("[bold green]Transforming binary..."):
        try:
            with MorphEngine() as engine:
                engine.load_binary(input_file).analyze()

                # Create configuration using factory methods
                if aggressive:
                    config = EngineConfig.create_aggressive()
                else:
                    config = EngineConfig.create_default()

                # Apply force flag if specified
                if force:
                    config.force_different = True
                    config.nop.force_different = True
                    config.substitution.force_different = True
                    config.register.force_different = True
                    config.expansion.force_different = True
                    config.block.force_different = True

                engine.add_mutation(NopInsertionPass(config=config.nop.to_dict()))
                engine.add_mutation(InstructionSubstitutionPass(config=config.substitution.to_dict()))
                engine.add_mutation(RegisterSubstitutionPass(config=config.register.to_dict()))
                engine.add_mutation(InstructionExpansionPass(config=config.expansion.to_dict()))
                engine.add_mutation(BlockReorderingPass(config=config.block.to_dict()))

                result = engine.run()

                engine.save(output_file)

            table = Table(title="Transformation Results")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Total Mutations", str(result.get("total_mutations", 0)))
            table.add_row("Passes Run", str(result.get("passes_run", 0)))

            for pass_name, pass_result in result.get("pass_results", {}).items():
                if "error" in pass_result:
                    table.add_row(f"{pass_name}", f"[red]Error: {pass_result['error']}[/red]")
                else:
                    table.add_row(
                        f"{pass_name} Mutations",
                        str(pass_result.get("mutations_applied", 0)),
                    )

            console.print(table)
            console.print(f"\n[bold green]✓[/bold green] Binary saved to: {output_file}")

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

        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)


@app.command()
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
    Enhanced analysis for obfuscated binaries (VMProtect, Themida, etc.).
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

            # Create and run the orchestrator
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
                    f"\n[yellow]Showing {limit} of {len(funcs)} functions. "
                    f"Use --limit to show more.[/yellow]"
                )

        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)


@app.command()
def morph(
    binary: Path = typer.Argument(..., help="Path to binary file", exists=True),
    output: Path = typer.Option(None, "--output", "-o", help="Output path for morphed binary"),
    mutations: list[str] = typer.Option(
        ["nop", "substitute"],
        "--mutation",
        "-m",
        help="Mutations to apply (nop, substitute, register, expand, block)",
    ),
    aggressive: bool = typer.Option(
        False, "--aggressive", "-a", help="Aggressive mode: more mutations"
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Force mutations to be different from original"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
):
    """
    Apply metamorphic transformations to a binary.

    Examples:
        r2morph morph binary.exe -o output.exe
        r2morph morph binary.exe -m nop -m substitute --aggressive
    """
    setup_logging("DEBUG" if verbose else "INFO")

    if not output:
        output = binary.parent / f"{binary.stem}_morphed{binary.suffix}"

    mode_str = (
        "[bold red]AGGRESSIVE[/bold red]" if aggressive else "[bold green]STANDARD[/bold green]"
    )
    console.print(f"[bold green]Starting binary transformation ({mode_str})[/bold green]")
    console.print(f"Input:  {binary}")
    console.print(f"Output: {output}")
    console.print(f"Mutations: {', '.join(mutations)}\n")

    with console.status("[bold green]Transforming binary..."):
        try:
            with MorphEngine() as engine:
                engine.load_binary(binary).analyze()

                # Create configuration using factory methods
                if aggressive:
                    config = EngineConfig.create_aggressive()
                else:
                    config = EngineConfig.create_default()

                # Apply force flag if specified
                if force:
                    config.force_different = True
                    config.nop.force_different = True
                    config.substitution.force_different = True
                    config.register.force_different = True
                    config.expansion.force_different = True
                    config.block.force_different = True

                if "nop" in mutations:
                    engine.add_mutation(NopInsertionPass(config=config.nop.to_dict()))

                if "substitute" in mutations:
                    engine.add_mutation(InstructionSubstitutionPass(config=config.substitution.to_dict()))

                if "register" in mutations:
                    engine.add_mutation(RegisterSubstitutionPass(config=config.register.to_dict()))

                if "expand" in mutations:
                    engine.add_mutation(InstructionExpansionPass(config=config.expansion.to_dict()))

                if "block" in mutations:
                    engine.add_mutation(BlockReorderingPass(config=config.block.to_dict()))

                result = engine.run()

                engine.save(output)

            table = Table(title="Transformation Results")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Total Mutations", str(result.get("total_mutations", 0)))
            table.add_row("Passes Run", str(result.get("passes_run", 0)))

            for pass_name, pass_result in result.get("pass_results", {}).items():
                if "error" in pass_result:
                    table.add_row(f"{pass_name}", f"[red]Error: {pass_result['error']}[/red]")
                else:
                    table.add_row(
                        f"{pass_name} Mutations",
                        str(pass_result.get("mutations_applied", 0)),
                    )

            console.print(table)
            console.print(f"\n[bold green]✓[/bold green] Binary saved to: {output}")

        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)


@app.command()
def version():
    """
    Display version information.
    """
    rprint(f"[bold cyan]r2morph[/bold cyan] version [green]{__version__}[/green]")
    rprint("A metamorphic binary transformation engine")


def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
