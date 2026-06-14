"""
Enhanced analysis orchestrator for obfuscated binaries.

This module provides an orchestrator class to coordinate enhanced binary analysis
including obfuscation detection, symbolic execution, dynamic instrumentation,
devirtualization, and reporting.
"""

import logging
from pathlib import Path
from typing import Any

from rich.console import Console

from r2morph.analysis.enhanced_analyzer_lifecycle import cleanup_binary, ensure_dependencies, load_binary
from r2morph.analysis.enhanced_analyzer_models import AnalysisOptions, AnalysisResults
from r2morph.analysis.enhanced_analyzer_phases import (
    run_binary_rewriting,
    run_cfo_simplification,
    run_dynamic_analysis,
    run_iterative_simplification,
    run_symbolic_analysis,
)
from r2morph.analysis.enhanced_analyzer_reporting import (
    display_analysis_results,
    display_detection_results,
    display_recommendations,
    generate_report,
    save_report,
)

logger = logging.getLogger(__name__)


class EnhancedAnalysisOrchestrator:
    """
    Orchestrates enhanced binary analysis with detection and reporting.

    This class coordinates the various analysis phases for obfuscated binaries,
    including packer detection, anti-analysis bypass, symbolic execution,
    dynamic instrumentation, devirtualization, and report generation.
    """

    def __init__(self, binary_path: Path, output_dir: Path | None = None, console: Console | None = None):
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
        self._binary: Any = None
        self._detector: Any = None

    def _ensure_dependencies(self) -> bool:
        return ensure_dependencies()

    def _load_binary(self) -> Any:
        self._binary = load_binary(self.binary_path)
        return self._binary

    def _cleanup(self) -> None:
        cleanup_binary(self._binary)
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

        self.results.custom_vm = self._detector.detect_custom_virtualizer(self._binary)
        self.results.layers = self._detector.detect_code_packing_layers(self._binary)
        self.results.metamorphic = self._detector.detect_metamorphic_engine(self._binary)

        return self.results.detection_result

    def display_detection_results(self, verbose: bool = False) -> None:
        """
        Display detection results to console.

        Args:
            verbose: Whether to show verbose output
        """
        display_detection_results(
            self.console,
            self.binary_path,
            self.results.detection_result,
            self.results.custom_vm,
            self.results.layers,
            self.results.metamorphic,
            verbose=verbose,
        )

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
            self.console.print(f"Applied {len(bypass_result.techniques_applied)} bypasses")
            return bypass_result
        else:
            self.console.print("No anti-analysis techniques detected")
            return None

    def run_cfo_simplification(self) -> int:
        return run_cfo_simplification(self._binary, self.console, self.results)

    def run_iterative_simplification(self, max_iterations: int = 5, timeout: int = 60) -> dict[str, Any] | None:
        return run_iterative_simplification(
            self._binary,
            self.console,
            self.results,
            max_iterations=max_iterations,
            timeout=timeout,
        )

    def run_symbolic_analysis(self) -> int | None:
        return run_symbolic_analysis(self._binary, self.console, self.results)

    def run_dynamic_analysis(self) -> bool:
        return run_dynamic_analysis(self.console)

    def run_binary_rewriting(self) -> str | None:
        return run_binary_rewriting(
            self._binary,
            self.binary_path,
            self.console,
            self.results,
            output_dir=self.output_dir,
        )

    def generate_report(self) -> dict[str, Any]:
        """
        Generate comprehensive analysis report.

        Returns:
            Complete analysis report dictionary
        """
        if self._detector is None:
            from r2morph.detection import ObfuscationDetector

            self._detector = ObfuscationDetector()

        return generate_report(self._detector, self._binary, self.results, self.console)

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

        return save_report(self.output_dir, report, self.console)

    def display_analysis_results(self) -> None:
        """Display advanced analysis results summary."""
        display_analysis_results(self.console, self.results)

    def display_recommendations(self) -> None:
        """Display mutation and analysis recommendations based on detection results."""
        display_recommendations(self.console, self.results.detection_result, self.results.layers)

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
            self._load_binary()
            self.run_detection()
            self.display_detection_results(verbose=options.verbose)

            if options.detect_only:
                return self.results

            result = self.results.detection_result

            if options.bypass:
                self.run_anti_analysis_bypass()

            if result.control_flow_flattened or options.devirt:
                self.run_cfo_simplification()

            if options.iterative:
                self.run_iterative_simplification(max_iterations=options.max_iterations, timeout=options.timeout)

            if options.symbolic and result.vm_detected:
                self.run_symbolic_analysis()

            if options.dynamic:
                self.run_dynamic_analysis()

            if options.rewrite:
                self.run_binary_rewriting()

            self.display_analysis_results()

            report = self.generate_report()

            if self.output_dir:
                self.save_report(report)

            self.display_recommendations()

            self.console.print("\n[bold green]Phase 2 Analysis Complete![/bold green]")
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
    import importlib.util

    return (
        importlib.util.find_spec("r2morph.detection") is not None
        and importlib.util.find_spec("r2morph.devirtualization") is not None
    )
