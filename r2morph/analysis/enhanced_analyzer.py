"""
Enhanced analysis orchestrator for obfuscated binaries.

This module provides an orchestrator class to coordinate enhanced binary analysis
including obfuscation detection, symbolic execution, dynamic instrumentation,
devirtualization, and reporting.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

logger = logging.getLogger(__name__)


@dataclass
class AnalysisOptions:
    """Options for the analysis orchestrator."""

    verbose: bool = False
    detect_only: bool = False
    symbolic: bool = False
    dynamic: bool = False
    devirt: bool = False
    iterative: bool = False
    rewrite: bool = False
    bypass: bool = False
    max_functions: int = 5
    max_iterations: int = 5
    timeout: int = 60


@dataclass
class AnalysisResults:
    """Container for all analysis results."""

    detection_result: Any = None
    custom_vm: dict[str, Any] = field(default_factory=dict)
    layers: dict[str, Any] = field(default_factory=dict)
    metamorphic: dict[str, Any] = field(default_factory=dict)
    cfo_reduction: int = 0
    iterative_result: dict[str, Any] | None = None
    vm_handlers: int = 0
    rewrite_output: str | None = None
    report: dict[str, Any] | None = None


class EnhancedAnalysisOrchestrator:
    """
    Orchestrates enhanced binary analysis with detection and reporting.

    This class coordinates the various analysis phases for obfuscated binaries,
    including packer detection, anti-analysis bypass, symbolic execution,
    dynamic instrumentation, devirtualization, and report generation.
    """

    def __init__(self, binary_path: Path, output_dir: Path | None = None,
                 console: Console | None = None):
        """
        Initialize the orchestrator.

        Args:
            binary_path: Path to the binary to analyze
            output_dir: Optional output directory for results
            console: Optional Rich console for output
        """
        self.binary_path = binary_path
        self.output_dir = output_dir
        self.console = console or Console()
        self.results = AnalysisResults()
        self._binary = None
        self._detector = None

    def _ensure_dependencies(self) -> bool:
        """
        Check and import enhanced analysis dependencies.

        Returns:
            True if dependencies are available, False otherwise
        """
        try:
            from r2morph.detection import ObfuscationDetector, AntiAnalysisBypass
            from r2morph.devirtualization import (
                CFOSimplifier,
                IterativeSimplifier,
                BinaryRewriter
            )
            return True
        except ImportError:
            return False

    def _load_binary(self):
        """Load and analyze the binary."""
        from r2morph import Binary

        self._binary = Binary(str(self.binary_path))
        self._binary.__enter__()
        self._binary.analyze()
        return self._binary

    def _cleanup(self):
        """Clean up resources."""
        if self._binary is not None:
            try:
                self._binary.__exit__(None, None, None)
            except Exception:
                pass
            self._binary = None

    def run_detection(self) -> Any:
        """
        Run obfuscation detection on the binary.

        Returns:
            ObfuscationAnalysisResult from the detector
        """
        from r2morph.detection import ObfuscationDetector

        self._detector = ObfuscationDetector()
        self.results.detection_result = self._detector.analyze_binary(self._binary)

        # Extended detection
        self.results.custom_vm = self._detector.detect_custom_virtualizer(self._binary)
        self.results.layers = self._detector.detect_code_packing_layers(self._binary)
        self.results.metamorphic = self._detector.detect_metamorphic_engine(self._binary)

        return self.results.detection_result

    def display_detection_results(self, verbose: bool = False):
        """
        Display detection results to console.

        Args:
            verbose: Whether to show verbose output
        """
        result = self.results.detection_result
        if result is None:
            return

        # Main detection table
        table = Table(title=f"Enhanced Analysis: {self.binary_path.name}")
        table.add_column("Detection", style="cyan")
        table.add_column("Result", style="green")

        table.add_row(
            "Packer Detected",
            result.packer_detected.value if result.packer_detected else "None"
        )
        table.add_row("VM Protection", "Yes" if result.vm_detected else "No")
        table.add_row("Anti-Analysis", "Yes" if result.anti_analysis_detected else "No")
        table.add_row(
            "Control Flow Flattening",
            "Yes" if result.control_flow_flattened else "No"
        )
        table.add_row("MBA Detected", "Yes" if result.mba_detected else "No")
        table.add_row("Confidence Score", f"{result.confidence_score:.2f}")
        table.add_row("Techniques Found", str(len(result.obfuscation_techniques)))

        self.console.print(table)

        # Extended detection info
        self.console.print("\n[bold cyan]Extended Detection:[/bold cyan]")

        if self.results.custom_vm.get('detected'):
            vm_type = self.results.custom_vm.get('vm_type', 'unknown')
            confidence = self.results.custom_vm.get('confidence', 0)
            self.console.print(f"  Custom Virtualizer: {vm_type} ({confidence:.2f})")

        if self.results.layers.get('layers_detected', 0) > 0:
            layers_count = self.results.layers['layers_detected']
            self.console.print(f"  Packing Layers: {layers_count}")

        if self.results.metamorphic.get('detected'):
            poly_ratio = self.results.metamorphic.get('polymorphic_ratio', 0)
            self.console.print(f"  Metamorphic Engine: {poly_ratio:.1%}")

        # Obfuscation techniques list
        if result.obfuscation_techniques:
            self.console.print("\n[bold cyan]Obfuscation Techniques:[/bold cyan]")
            for i, technique in enumerate(result.obfuscation_techniques[:10], 1):
                self.console.print(f"  {i}. {technique}")
            if len(result.obfuscation_techniques) > 10:
                remaining = len(result.obfuscation_techniques) - 10
                self.console.print(f"  ... and {remaining} more")

    def run_anti_analysis_bypass(self) -> Any | None:
        """
        Apply anti-analysis bypass techniques.

        Returns:
            BypassResult if bypasses were applied, None otherwise
        """
        from r2morph.detection import AntiAnalysisBypass

        self.console.print("\n[bold yellow]Applying Anti-Analysis Bypass...[/bold yellow]")
        bypass_framework = AntiAnalysisBypass()
        detected_techniques = bypass_framework.detect_anti_analysis_techniques(self._binary)

        if detected_techniques:
            bypass_result = bypass_framework.apply_comprehensive_bypass(detected_techniques)
            self.console.print(
                f"Applied {len(bypass_result.techniques_applied)} bypasses"
            )
            return bypass_result
        else:
            self.console.print("No anti-analysis techniques detected")
            return None

    def run_cfo_simplification(self) -> int:
        """
        Run Control Flow Obfuscation simplification.

        Returns:
            Total complexity reduction achieved
        """
        from r2morph.devirtualization import CFOSimplifier

        self.console.print("\n[bold yellow]Running CFO simplification...[/bold yellow]")
        try:
            cfo_simplifier = CFOSimplifier(self._binary)
            functions = self._binary.get_functions()[:5]  # Limit for performance

            total_reduction = 0
            for func in functions:
                func_addr = func.get('offset', 0)
                result = cfo_simplifier.simplify_control_flow(func_addr)
                if result.success:
                    reduction = result.original_complexity - result.simplified_complexity
                    total_reduction += reduction

            if total_reduction > 0:
                self.console.print(
                    f"CFO simplification: {total_reduction} complexity reduced"
                )

            self.results.cfo_reduction = total_reduction
            return total_reduction

        except Exception as e:
            self.console.print(f"[yellow]CFO simplification error: {e}[/yellow]")
            return 0

    def run_iterative_simplification(self, max_iterations: int = 5,
                                      timeout: int = 60) -> dict[str, Any] | None:
        """
        Run iterative simplification passes.

        Args:
            max_iterations: Maximum number of simplification iterations
            timeout: Timeout in seconds for the simplification

        Returns:
            Simplification metrics if successful, None otherwise
        """
        from r2morph.devirtualization import IterativeSimplifier
        from r2morph.devirtualization.iterative_simplifier import SimplificationStrategy

        self.console.print("\n[bold yellow]Running iterative simplification...[/bold yellow]")
        try:
            simplifier = IterativeSimplifier(self._binary)
            result = simplifier.simplify(
                strategy=SimplificationStrategy.ADAPTIVE,
                max_iterations=max_iterations,
                timeout=timeout
            )

            if result.success:
                self.console.print("Iterative simplification completed:")
                self.console.print(f"   Iterations: {result.metrics.iteration}")
                self.console.print(
                    f"   Complexity reduction: {result.metrics.complexity_reduction:.1%}"
                )
                self.results.iterative_result = result.metrics.__dict__
                return result.metrics.__dict__
            else:
                self.console.print("Iterative simplification failed")
                return None

        except Exception as e:
            self.console.print(f"[yellow]Iterative simplification error: {e}[/yellow]")
            return None

    def run_symbolic_analysis(self) -> int | None:
        """
        Run symbolic execution analysis.

        Returns:
            Number of VM handlers found, or None if unavailable
        """
        try:
            from r2morph.analysis.symbolic import AngrBridge, PathExplorer

            self.console.print("\n[bold yellow]Running symbolic execution...[/bold yellow]")

            angr_bridge = AngrBridge(self._binary)
            if angr_bridge.angr_project:
                path_explorer = PathExplorer(angr_bridge)
                functions = self._binary.get_functions()
                if functions:
                    dispatcher_addr = functions[0].get("offset", 0)
                else:
                    dispatcher_addr = self._binary.get_entrypoint()

                handlers = path_explorer.find_vm_handlers(dispatcher_addr, max_handlers=5)
                handlers_count = len(handlers)
                if handlers_count:
                    self.results.vm_handlers = handlers_count
                    self.console.print(f"Found {handlers_count} VM handlers")
                    return handlers_count
            return None

        except ImportError:
            self.console.print(
                "[yellow]Symbolic execution not available (missing angr)[/yellow]"
            )
            return None

    def run_dynamic_analysis(self) -> bool:
        """
        Set up and run dynamic instrumentation.

        Returns:
            True if Frida engine was initialized, False otherwise
        """
        try:
            from r2morph.instrumentation import FridaEngine

            self.console.print(
                "\n[bold yellow]Setting up dynamic instrumentation...[/bold yellow]"
            )

            frida_engine = FridaEngine()
            self.console.print("Frida engine initialized")
            return True

        except ImportError:
            self.console.print(
                "[yellow]Dynamic instrumentation not available (missing frida)[/yellow]"
            )
            return False

    def run_binary_rewriting(self) -> str | None:
        """
        Perform binary rewriting and reconstruction.

        Returns:
            Path to rewritten binary if successful, None otherwise
        """
        from r2morph.devirtualization import BinaryRewriter

        self.console.print("\n[bold yellow]Performing binary rewriting...[/bold yellow]")
        try:
            rewriter = BinaryRewriter(self._binary)

            # Set up output path
            if self.output_dir:
                output_path = (
                    self.output_dir /
                    f"{self.binary_path.stem}_rewritten{self.binary_path.suffix}"
                )
            else:
                output_path = (
                    self.binary_path.parent /
                    f"{self.binary_path.stem}_rewritten{self.binary_path.suffix}"
                )

            # Add example patches
            functions = self._binary.get_functions()[:3]
            patches_added = 0
            for func in functions:
                func_addr = func.get('offset', 0)
                if rewriter.add_patch(func_addr, ["nop"]):
                    patches_added += 1

            # Perform rewriting
            rewrite_result = rewriter.rewrite_binary(str(output_path))

            if rewrite_result.success:
                self.console.print(f"Binary rewritten to {output_path}")
                self.console.print(f"   Patches applied: {rewrite_result.patches_applied}")
                self.results.rewrite_output = str(output_path)
                return str(output_path)
            else:
                self.console.print("Binary rewriting failed")
                return None

        except Exception as e:
            self.console.print(f"[yellow]Binary rewriting error: {e}[/yellow]")
            return None

    def generate_report(self) -> dict[str, Any]:
        """
        Generate comprehensive analysis report.

        Returns:
            Complete analysis report dictionary
        """
        if self._detector is None:
            from r2morph.detection import ObfuscationDetector
            self._detector = ObfuscationDetector()

        self.console.print("\n[bold yellow]Generating comprehensive report...[/bold yellow]")
        report = self._detector.get_comprehensive_report(self._binary)
        self.results.report = report
        return report

    def save_report(self, report: dict[str, Any]) -> Path | None:
        """
        Save analysis report to file.

        Args:
            report: Report dictionary to save

        Returns:
            Path to saved report if successful, None otherwise
        """
        if not self.output_dir:
            return None

        self.output_dir.mkdir(exist_ok=True)
        report_path = self.output_dir / "analysis_report.json"

        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        self.console.print(f"Report saved to {report_path}")
        return report_path

    def display_analysis_results(self):
        """Display advanced analysis results summary."""
        results_dict = {}

        if self.results.cfo_reduction > 0:
            results_dict['cfo_reduction'] = self.results.cfo_reduction

        if self.results.iterative_result:
            results_dict['iterative_result'] = self.results.iterative_result

        if self.results.vm_handlers > 0:
            results_dict['vm_handlers'] = self.results.vm_handlers

        if self.results.rewrite_output:
            results_dict['rewrite_output'] = self.results.rewrite_output

        if results_dict:
            self.console.print("\n[bold cyan]Advanced Analysis Results:[/bold cyan]")
            for key, value in results_dict.items():
                self.console.print(f"  {key}: {value}")

    def display_recommendations(self):
        """Display mutation and analysis recommendations based on detection results."""
        result = self.results.detection_result
        if result is None:
            return

        self.console.print("\n[bold cyan]Recommendations:[/bold cyan]")

        if result.vm_detected:
            self.console.print(
                "  - VM protection detected - use --devirt --iterative for comprehensive analysis"
            )

        if result.anti_analysis_detected:
            self.console.print(
                "  - Anti-analysis techniques detected - use --bypass --dynamic"
            )

        if result.mba_detected:
            self.console.print(
                "  - MBA expressions detected - use --iterative for expression simplification"
            )

        if result.control_flow_flattened:
            self.console.print(
                "  - Control flow flattening detected - use --symbolic --devirt"
            )

        layers_detected = self.results.layers.get('layers_detected', 0)
        if layers_detected > 1:
            self.console.print(
                "  - Multiple packing layers detected - iterative unpacking recommended"
            )

        # Check if binary appears lightly obfuscated
        if not any([
            result.vm_detected,
            result.anti_analysis_detected,
            result.mba_detected,
            result.control_flow_flattened
        ]):
            self.console.print(
                "  - Binary appears lightly obfuscated - standard analysis may suffice"
            )

    def analyze(self, options: AnalysisOptions | None = None) -> AnalysisResults:
        """
        Main analysis entry point - orchestrates all analysis phases.

        Args:
            options: Analysis options controlling which phases to run

        Returns:
            AnalysisResults containing all analysis output
        """
        if options is None:
            options = AnalysisOptions()

        try:
            # Load the binary
            self._load_binary()

            # Step 1: Enhanced Obfuscation Detection
            self.run_detection()
            self.display_detection_results(verbose=options.verbose)

            if options.detect_only:
                return self.results

            result = self.results.detection_result

            # Step 2: Anti-Analysis Bypass
            if options.bypass:
                self.run_anti_analysis_bypass()

            # Step 3: Advanced Analysis

            # Control Flow Obfuscation Simplification
            if result.control_flow_flattened or options.devirt:
                self.run_cfo_simplification()

            # Iterative Simplification
            if options.iterative:
                self.run_iterative_simplification(
                    max_iterations=options.max_iterations,
                    timeout=options.timeout
                )

            # Symbolic Execution
            if options.symbolic and result.vm_detected:
                self.run_symbolic_analysis()

            # Dynamic Instrumentation
            if options.dynamic:
                self.run_dynamic_analysis()

            # Binary Rewriting
            if options.rewrite:
                self.run_binary_rewriting()

            # Display analysis results summary
            self.display_analysis_results()

            # Step 4: Comprehensive Report
            report = self.generate_report()

            if self.output_dir:
                self.save_report(report)

            # Step 5: Recommendations
            self.display_recommendations()

            self.console.print(f"\n[bold green]Phase 2 Analysis Complete![/bold green]")
            if self.output_dir:
                self.console.print(f"Results saved to: {self.output_dir}")

            return self.results

        finally:
            self._cleanup()


def check_enhanced_dependencies() -> bool:
    """
    Check if enhanced analysis dependencies are available.

    Returns:
        True if dependencies are available, False otherwise
    """
    try:
        from r2morph.detection import ObfuscationDetector, AntiAnalysisBypass
        from r2morph.devirtualization import (
            CFOSimplifier,
            IterativeSimplifier,
            BinaryRewriter
        )
        return True
    except ImportError:
        return False
