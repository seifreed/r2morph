"""Phase execution helpers for enhanced binary analysis."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path
from typing import Any, cast


def run_cfo_simplification(binary: Any, console: Any, results: Any) -> int:
    """Run Control Flow Obfuscation simplification."""
    cfo_simplifier_cls = import_module("r2morph.devirtualization").CFOSimplifier
    console.print("\n[bold yellow]Running CFO simplification...[/bold yellow]")
    try:
        cfo_simplifier = cfo_simplifier_cls(binary)
        functions = binary.get_functions()[:5]  # Limit for performance

        total_reduction = 0
        for func in functions:
            func_addr = func.get("offset", 0)
            result = cfo_simplifier.simplify_control_flow(func_addr)
            if result.success:
                reduction = result.original_complexity - result.simplified_complexity
                total_reduction += reduction

        if total_reduction > 0:
            console.print(f"CFO simplification: {total_reduction} complexity reduced")

        results.cfo_reduction = total_reduction
        return total_reduction

    except Exception as e:
        console.print(f"[yellow]CFO simplification error: {e}[/yellow]")
        return 0


def run_iterative_simplification(
    binary: Any,
    console: Any,
    results: Any,
    *,
    max_iterations: int = 5,
    timeout: int = 60,
) -> dict[str, Any] | None:
    """Run iterative simplification passes."""
    iterative_simplifier_cls = import_module("r2morph.devirtualization").IterativeSimplifier
    simplification_strategy = import_module(
        "r2morph.devirtualization.iterative_simplifier_models"
    ).SimplificationStrategy

    console.print("\n[bold yellow]Running iterative simplification...[/bold yellow]")
    try:
        simplifier = iterative_simplifier_cls(binary)
        result = simplifier.simplify(
            strategy=simplification_strategy.ADAPTIVE,
            max_iterations=max_iterations,
            timeout=timeout,
        )

        if result.success:
            console.print("Iterative simplification completed:")
            console.print(f"   Iterations: {result.metrics.iteration}")
            console.print(f"   Complexity reduction: {result.metrics.complexity_reduction:.1%}")
            metrics = cast(dict[str, Any], result.metrics.__dict__)
            results.iterative_result = metrics
            return metrics

        console.print("Iterative simplification failed")
        return None

    except Exception as e:
        console.print(f"[yellow]Iterative simplification error: {e}[/yellow]")
        return None


def run_symbolic_analysis(binary: Any, console: Any, results: Any) -> int | None:
    """Run symbolic execution analysis."""
    try:
        symbolic_module = import_module("r2morph.analysis.symbolic")

        console.print("\n[bold yellow]Running symbolic execution...[/bold yellow]")

        if binary is None:
            return None
        angr_bridge = symbolic_module.AngrBridge(binary)
        if angr_bridge.angr_project:
            path_explorer = symbolic_module.PathExplorer(angr_bridge)
            functions = binary.get_functions()
            dispatcher_addr = functions[0].get("offset", 0) if functions else binary.get_entrypoint()

            handlers = path_explorer.find_vm_handlers(dispatcher_addr, max_handlers=5)
            handlers_count = len(handlers)
            if handlers_count:
                results.vm_handlers = handlers_count
                console.print(f"Found {handlers_count} VM handlers")
                return handlers_count
        return None

    except ImportError:
        console.print("[yellow]Symbolic execution not available (missing angr)[/yellow]")
        return None


def run_dynamic_analysis(console: Any) -> bool:
    """Set up and run dynamic instrumentation."""
    try:
        frida_engine_cls = import_module("r2morph.instrumentation").FridaEngine

        console.print("\n[bold yellow]Setting up dynamic instrumentation...[/bold yellow]")

        frida_engine_cls()
        console.print("Frida engine initialized")
        return True

    except ImportError:
        console.print("[yellow]Dynamic instrumentation not available (missing frida)[/yellow]")
        return False


def run_binary_rewriting(
    binary: Any,
    binary_path: Path,
    console: Any,
    results: Any,
    *,
    output_dir: Path | None = None,
) -> str | None:
    """Perform binary rewriting and reconstruction."""
    binary_rewriter_cls = import_module("r2morph.devirtualization").BinaryRewriter
    console.print("\n[bold yellow]Performing binary rewriting...[/bold yellow]")
    try:
        rewriter = binary_rewriter_cls(binary)

        if output_dir:
            output_path = output_dir / f"{binary_path.stem}_rewritten{binary_path.suffix}"
        else:
            output_path = binary_path.parent / f"{binary_path.stem}_rewritten{binary_path.suffix}"

        functions = binary.get_functions()[:3]
        for func in functions:
            func_addr = func.get("offset", 0)
            rewriter.add_patch(func_addr, ["nop"])

        rewrite_result = rewriter.rewrite_binary(str(output_path))

        if rewrite_result.success:
            console.print(f"Binary rewritten to {output_path}")
            console.print(f"   Patches applied: {rewrite_result.patches_applied}")
            results.rewrite_output = str(output_path)
            return str(output_path)

        console.print("Binary rewriting failed")
        return None

    except Exception as e:
        console.print(f"[yellow]Binary rewriting error: {e}[/yellow]")
        return None
