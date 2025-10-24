"""
Command-line interface for r2morph.

Ultra-simple usage (like r2morph):
    r2morph input.exe [output.exe]

Advanced usage:
    r2morph morph input.exe -o output.exe -m nop -m substitute
"""

from pathlib import Path
from typing import List, Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from r2morph import __version__
from r2morph.analysis.analyzer import BinaryAnalyzer
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

                if aggressive:
                    nop_config = {
                        "max_nops_per_function": 20,
                        "probability": 0.95,
                        "use_creative_nops": True,
                        "force_different": force,
                    }
                    subst_config = {
                        "max_substitutions_per_function": 30,
                        "probability": 0.95,
                        "force_different": force,
                    }
                    reg_config = {
                        "max_substitutions_per_function": 15,
                        "probability": 0.9,
                        "force_different": force,
                    }
                    exp_config = {
                        "max_expansions_per_function": 15,
                        "probability": 0.9,
                        "force_different": force,
                    }
                    block_config = {
                        "max_reorderings_per_function": 8,
                        "probability": 0.8,
                        "force_different": force,
                    }
                else:
                    nop_config = {
                        "max_nops_per_function": 5,
                        "probability": 0.5,
                        "use_creative_nops": True,
                        "force_different": force,
                    }
                    subst_config = {
                        "max_substitutions_per_function": 10,
                        "probability": 0.7,
                        "force_different": force,
                    }
                    reg_config = {
                        "max_substitutions_per_function": 5,
                        "probability": 0.5,
                        "force_different": force,
                    }
                    exp_config = {
                        "max_expansions_per_function": 5,
                        "probability": 0.5,
                        "force_different": force,
                    }
                    block_config = {
                        "max_reorderings_per_function": 3,
                        "probability": 0.3,
                        "force_different": force,
                    }

                engine.add_mutation(NopInsertionPass(config=nop_config))
                engine.add_mutation(InstructionSubstitutionPass(config=subst_config))
                engine.add_mutation(RegisterSubstitutionPass(config=reg_config))
                engine.add_mutation(InstructionExpansionPass(config=exp_config))
                engine.add_mutation(BlockReorderingPass(config=block_config))

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

    try:
        from r2morph.detection import ObfuscationDetector, AntiAnalysisBypass
        from r2morph.devirtualization import CFOSimplifier, IterativeSimplifier, BinaryRewriter
    except ImportError:
        console.print("[bold red]Error:[/bold red] Enhanced analysis requires additional dependencies.")
        console.print("Install with: [cyan]pip install 'r2morph[enhanced]'[/cyan]")
        raise typer.Exit(1)

    with console.status("[bold green]Analyzing obfuscated binary..."):
        try:
            from r2morph import Binary
            
            with Binary(str(binary)) as bin_obj:
                bin_obj.analyze()
                
                # Step 1: Enhanced Obfuscation Detection
                detector = ObfuscationDetector()
                detection_result = detector.analyze_binary(bin_obj)
                
                # Display detection results
                table = Table(title=f"Enhanced Analysis: {binary.name}")
                table.add_column("Detection", style="cyan")
                table.add_column("Result", style="green")
                
                table.add_row("Packer Detected", detection_result.packer_detected.value if detection_result.packer_detected else "None")
                table.add_row("VM Protection", "Yes" if detection_result.vm_detected else "No")
                table.add_row("Anti-Analysis", "Yes" if detection_result.anti_analysis_detected else "No")
                table.add_row("Control Flow Flattening", "Yes" if detection_result.control_flow_flattened else "No")
                table.add_row("MBA Detected", "Yes" if detection_result.mba_detected else "No")
                table.add_row("Confidence Score", f"{detection_result.confidence_score:.2f}")
                table.add_row("Techniques Found", str(len(detection_result.obfuscation_techniques)))
                
                console.print(table)
                
                # Extended detection
                console.print("\n[bold cyan]Extended Detection:[/bold cyan]")
                
                # Custom virtualizer detection
                custom_vm = detector.detect_custom_virtualizer(bin_obj)
                if custom_vm['detected']:
                    console.print(f"  🤖 Custom Virtualizer: {custom_vm['vm_type']} ({custom_vm['confidence']:.2f})")
                
                # Layer analysis
                layers = detector.detect_code_packing_layers(bin_obj)
                if layers['layers_detected'] > 0:
                    console.print(f"  📚 Packing Layers: {layers['layers_detected']}")
                
                # Metamorphic detection
                metamorphic = detector.detect_metamorphic_engine(bin_obj)
                if metamorphic['detected']:
                    console.print(f"  🧬 Metamorphic Engine: {metamorphic['polymorphic_ratio']:.1%}")
                
                if detection_result.obfuscation_techniques:
                    console.print("\n[bold cyan]Obfuscation Techniques:[/bold cyan]")
                    for i, technique in enumerate(detection_result.obfuscation_techniques[:10], 1):
                        console.print(f"  {i}. {technique}")
                    if len(detection_result.obfuscation_techniques) > 10:
                        console.print(f"  ... and {len(detection_result.obfuscation_techniques) - 10} more")
                
                if detect_only:
                    return
                
                # Step 2: Anti-Analysis Bypass
                if bypass:
                    console.print("\n[bold yellow]Applying Anti-Analysis Bypass...[/bold yellow]")
                    bypass_framework = AntiAnalysisBypass()
                    detected_techniques = bypass_framework.detect_anti_analysis_techniques(bin_obj)
                    
                    if detected_techniques:
                        bypass_result = bypass_framework.apply_comprehensive_bypass(detected_techniques)
                        console.print(f"✅ Applied {len(bypass_result.techniques_applied)} bypasses")
                    else:
                        console.print("✅ No anti-analysis techniques detected")
                
                # Step 3: Advanced Analysis
                analysis_results = {}
                
                # Control Flow Obfuscation Simplification
                if detection_result.control_flow_flattened or devirt:
                    console.print("\n[bold yellow]Running CFO simplification...[/bold yellow]")
                    try:
                        cfo_simplifier = CFOSimplifier(bin_obj)
                        functions = bin_obj.get_functions()[:5]  # Limit for demo
                        
                        total_reduction = 0
                        for func in functions:
                            func_addr = func.get('offset', 0)
                            result = cfo_simplifier.simplify_control_flow(func_addr)
                            if result.success:
                                reduction = result.original_complexity - result.simplified_complexity
                                total_reduction += reduction
                        
                        if total_reduction > 0:
                            console.print(f"✅ CFO simplification: {total_reduction} complexity reduced")
                        analysis_results['cfo_reduction'] = total_reduction
                        
                    except Exception as e:
                        console.print(f"[yellow]CFO simplification error: {e}[/yellow]")
                
                # Iterative Simplification
                if iterative:
                    console.print("\n[bold yellow]Running iterative simplification...[/bold yellow]")
                    try:
                        from r2morph.devirtualization import SimplificationStrategy
                        
                        simplifier = IterativeSimplifier(bin_obj)
                        result = simplifier.simplify(
                            strategy=SimplificationStrategy.ADAPTIVE,
                            max_iterations=5,  # Reduced for demo
                            timeout=60
                        )
                        
                        if result.success:
                            console.print(f"✅ Iterative simplification completed:")
                            console.print(f"   Iterations: {result.metrics.iteration}")
                            console.print(f"   Complexity reduction: {result.metrics.complexity_reduction:.1%}")
                            analysis_results['iterative_result'] = result.metrics.__dict__
                        else:
                            console.print(f"❌ Iterative simplification failed")
                    
                    except Exception as e:
                        console.print(f"[yellow]Iterative simplification error: {e}[/yellow]")
                
                # Symbolic Execution
                if symbolic and detection_result.vm_detected:
                    try:
                        from r2morph.analysis.symbolic import AngrBridge, PathExplorer
                        console.print("\n[bold yellow]Running symbolic execution...[/bold yellow]")
                        
                        angr_bridge = AngrBridge(bin_obj)
                        if angr_bridge.project:
                            path_explorer = PathExplorer(angr_bridge)
                            sym_result = path_explorer.explore_vm_handlers()
                            if sym_result:
                                analysis_results['vm_handlers'] = len(sym_result.vm_handlers_found)
                                console.print(f"✅ Found {len(sym_result.vm_handlers_found)} VM handlers")
                    except ImportError:
                        console.print("[yellow]Symbolic execution not available (missing angr)[/yellow]")
                
                # Dynamic Instrumentation
                if dynamic:
                    try:
                        from r2morph.instrumentation import FridaEngine
                        console.print("\n[bold yellow]Setting up dynamic instrumentation...[/bold yellow]")
                        
                        frida_engine = FridaEngine()
                        console.print("✅ Frida engine initialized")
                    except ImportError:
                        console.print("[yellow]Dynamic instrumentation not available (missing frida)[/yellow]")
                
                # Binary Rewriting
                if rewrite:
                    console.print("\n[bold yellow]Performing binary rewriting...[/bold yellow]")
                    try:
                        rewriter = BinaryRewriter(bin_obj)
                        
                        # Set up output path
                        if output:
                            output_path = Path(output) / f"{binary.stem}_rewritten{binary.suffix}"
                        else:
                            output_path = binary.parent / f"{binary.stem}_rewritten{binary.suffix}"
                        
                        # Add example patches
                        functions = bin_obj.get_functions()[:3]
                        patches_added = 0
                        for func in functions:
                            func_addr = func.get('offset', 0)
                            if rewriter.add_patch(func_addr, ["nop"]):
                                patches_added += 1
                        
                        # Perform rewriting
                        rewrite_result = rewriter.rewrite_binary(str(output_path))
                        
                        if rewrite_result.success:
                            console.print(f"✅ Binary rewritten to {output_path}")
                            console.print(f"   Patches applied: {rewrite_result.patches_applied}")
                            analysis_results['rewrite_output'] = str(output_path)
                        else:
                            console.print("❌ Binary rewriting failed")
                    
                    except Exception as e:
                        console.print(f"[yellow]Binary rewriting error: {e}[/yellow]")
                
                if analysis_results:
                    console.print("\n[bold cyan]Advanced Analysis Results:[/bold cyan]")
                    for key, value in analysis_results.items():
                        console.print(f"  {key}: {value}")
                
                # Step 4: Comprehensive Report
                console.print("\n[bold yellow]Generating comprehensive report...[/bold yellow]")
                report = detector.get_comprehensive_report(bin_obj)
                
                # Save report if output specified
                if output:
                    output_dir = Path(output)
                    output_dir.mkdir(exist_ok=True)
                    
                    report_path = output_dir / "analysis_report.json"
                    with open(report_path, 'w') as f:
                        import json
                        json.dump(report, f, indent=2, default=str)
                    
                    console.print(f"📊 Report saved to {report_path}")
                
                # Step 5: Recommendations
                console.print("\n[bold cyan]Recommendations:[/bold cyan]")
                
                if detection_result.vm_detected:
                    console.print("  • VM protection detected - use --devirt --iterative for comprehensive analysis")
                
                if detection_result.anti_analysis_detected:
                    console.print("  • Anti-analysis techniques detected - use --bypass --dynamic")
                
                if detection_result.mba_detected:
                    console.print("  • MBA expressions detected - use --iterative for expression simplification")
                
                if detection_result.control_flow_flattened:
                    console.print("  • Control flow flattening detected - use --symbolic --devirt")
                
                if layers['layers_detected'] > 1:
                    console.print("  • Multiple packing layers detected - iterative unpacking recommended")
                
                if not any([detection_result.vm_detected, detection_result.anti_analysis_detected, 
                           detection_result.mba_detected, detection_result.control_flow_flattened]):
                    console.print("  • Binary appears lightly obfuscated - standard analysis may suffice")
                
                console.print(f"\n[bold green]Phase 2 Analysis Complete![/bold green]")
                if output:
                    console.print(f"Results saved to: {output}")

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

                if aggressive:
                    nop_config = {
                        "max_nops_per_function": 20,
                        "probability": 0.95,
                        "use_creative_nops": True,
                        "force_different": force,
                    }
                    subst_config = {
                        "max_substitutions_per_function": 30,
                        "probability": 0.95,
                        "force_different": force,
                    }
                    reg_config = {
                        "max_substitutions_per_function": 15,
                        "probability": 0.9,
                        "force_different": force,
                    }
                    exp_config = {
                        "max_expansions_per_function": 15,
                        "probability": 0.9,
                        "force_different": force,
                    }
                    block_config = {
                        "max_reorderings_per_function": 8,
                        "probability": 0.8,
                        "force_different": force,
                    }
                else:
                    nop_config = {
                        "max_nops_per_function": 5,
                        "probability": 0.5,
                        "use_creative_nops": True,
                        "force_different": force,
                    }
                    subst_config = {
                        "max_substitutions_per_function": 10,
                        "probability": 0.7,
                        "force_different": force,
                    }
                    reg_config = {
                        "max_substitutions_per_function": 5,
                        "probability": 0.5,
                        "force_different": force,
                    }
                    exp_config = {
                        "max_expansions_per_function": 5,
                        "probability": 0.5,
                        "force_different": force,
                    }
                    block_config = {
                        "max_reorderings_per_function": 3,
                        "probability": 0.3,
                        "force_different": force,
                    }

                if "nop" in mutations:
                    engine.add_mutation(NopInsertionPass(config=nop_config))

                if "substitute" in mutations:
                    engine.add_mutation(InstructionSubstitutionPass(config=subst_config))

                if "register" in mutations:
                    engine.add_mutation(RegisterSubstitutionPass(config=reg_config))

                if "expand" in mutations:
                    engine.add_mutation(InstructionExpansionPass(config=exp_config))

                if "block" in mutations:
                    engine.add_mutation(BlockReorderingPass(config=block_config))

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
