"""
Real-world validation and benchmarking framework for r2morph.

This module provides comprehensive testing capabilities including:
- Performance benchmarking
- Accuracy metrics against known samples
- Regression testing
- Real-world validation scenarios
"""

import logging
import time
from pathlib import Path
from typing import Any

from r2morph.validation.benchmark_metrics import (
    calculate_accuracy_metrics,
    measure_performance,
)
from r2morph.validation.benchmark_reporting import (
    export_results as export_benchmark_results,
)
from r2morph.validation.benchmark_reporting import (
    generate_report as generate_benchmark_report,
)
from r2morph.validation.benchmark_reporting import (
    generate_validation_summary,
)
from r2morph.validation.benchmark_samples import DEFAULT_TEST_SAMPLES
from r2morph.validation.benchmark_types import (
    AccuracyMetrics,
    BenchmarkCategory,
    BenchmarkResult,
    PerformanceMetrics,
    TestSample,
)

logger = logging.getLogger(__name__)


class ValidationFramework:
    """
    Comprehensive validation framework for r2morph analysis capabilities.
    """

    def __init__(self, test_data_dir: str | None = None) -> None:
        """
        Initialize the validation framework.

        Args:
            test_data_dir: Directory containing test samples
        """
        self.test_data_dir = Path(test_data_dir) if test_data_dir else Path("dataset")
        self.test_samples: list[TestSample] = []
        self.benchmark_results: list[BenchmarkResult] = []

        self._load_test_samples()

    def _load_test_samples(self) -> None:
        """Load predefined test samples."""
        self.test_samples = [
            TestSample(
                file_path=str(self.test_data_dir / Path(data["file_path"])),
                sample_hash=str(data["sample_hash"]),
                expected_packer=data["expected_packer"],
                expected_vm_protection=bool(data["expected_vm_protection"]),
                expected_anti_analysis=bool(data["expected_anti_analysis"]),
                expected_cfo=bool(data["expected_cfo"]),
                expected_mba=bool(data["expected_mba"]),
                severity=data["severity"],
                description=str(data["description"]),
                source=str(data["source"]),
            )
            for data in DEFAULT_TEST_SAMPLES
        ]

    def add_test_sample(self, sample: TestSample) -> None:
        """Add a new test sample."""
        self.test_samples.append(sample)

    def _measure_performance(self, func: Any, *args: Any, **kwargs: Any) -> tuple[PerformanceMetrics, Any]:
        """
        Measure performance metrics for a function execution.

        Args:
            func: Function to measure
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            PerformanceMetrics object
        """
        return measure_performance(func, *args, **kwargs)

    def _calculate_percentile(self, values: list[float], percentile: int) -> float:
        """Compatibility delegator for benchmark percentile calculations."""
        from r2morph.validation.benchmark_reporting import calculate_percentile

        return calculate_percentile(values, percentile)

    def _calculate_accuracy_metrics(self, expected: dict[str, Any], actual: dict[str, Any]) -> AccuracyMetrics:
        """
        Calculate accuracy metrics by comparing expected vs actual results.

        Args:
            expected: Expected analysis results
            actual: Actual analysis results

        Returns:
            AccuracyMetrics object
        """
        return calculate_accuracy_metrics(expected, actual)

    def benchmark_detection(self, sample: TestSample) -> BenchmarkResult:
        """
        Benchmark obfuscation detection on a sample.

        Args:
            sample: Test sample to analyze

        Returns:
            BenchmarkResult
        """
        from r2morph import Binary
        from r2morph.detection import ObfuscationDetector

        def run_detection() -> dict[str, Any]:
            with Binary(sample.file_path) as bin_obj:
                bin_obj.analyze()
                detector = ObfuscationDetector()
                result = detector.analyze_binary(bin_obj)

                return {
                    "packer_detected": result.packer_detected.value if result.packer_detected else None,
                    "vm_protection": result.vm_detected,
                    "anti_analysis": result.anti_analysis_detected,
                    "cfo_detected": result.control_flow_flattened,
                    "mba_detected": result.mba_detected,
                    "confidence_score": result.confidence_score,
                    "techniques_count": len(result.obfuscation_techniques),
                }

        performance, analysis_result = self._measure_performance(run_detection)

        accuracy = None
        if performance.success and analysis_result:
            expected = {
                "packer_detected": sample.expected_packer,
                "vm_protection": sample.expected_vm_protection,
                "anti_analysis": sample.expected_anti_analysis,
                "cfo_detected": sample.expected_cfo,
                "mba_detected": sample.expected_mba,
            }
            accuracy = self._calculate_accuracy_metrics(expected, analysis_result)

        return BenchmarkResult(
            sample=sample,
            category=BenchmarkCategory.DETECTION,
            performance=performance,
            accuracy=accuracy,
            analysis_result=analysis_result or {},
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            r2morph_version="2.0.0-phase2",
        )

    def benchmark_devirtualization(self, sample: TestSample) -> BenchmarkResult:
        """
        Benchmark devirtualization capabilities on a sample.

        Args:
            sample: Test sample to analyze

        Returns:
            BenchmarkResult
        """
        from r2morph import Binary
        from r2morph.devirtualization import CFOSimplifier, IterativeSimplifier
        from r2morph.devirtualization.iterative_simplifier import SimplificationStrategy

        def run_devirtualization() -> dict[str, Any]:
            with Binary(sample.file_path) as bin_obj:
                bin_obj.analyze()

                cfo_simplifier = CFOSimplifier(bin_obj)
                functions = bin_obj.get_functions()[:3]

                cfo_results = []
                for func in functions:
                    func_addr = func.get("offset", 0)
                    result = cfo_simplifier.simplify_control_flow(func_addr)
                    if result.success:
                        cfo_results.append(
                            {
                                "function": func_addr,
                                "complexity_reduction": result.original_complexity - result.simplified_complexity,
                                "patterns_detected": len(result.patterns_detected),
                            }
                        )

                iterative_simplifier = IterativeSimplifier(bin_obj)
                iter_result = iterative_simplifier.simplify(
                    strategy=SimplificationStrategy.ADAPTIVE, max_iterations=3, timeout=30
                )

                return {
                    "cfo_functions_simplified": len(cfo_results),
                    "cfo_total_complexity_reduction": sum(r["complexity_reduction"] for r in cfo_results),
                    "iterative_success": iter_result.success,
                    "iterative_iterations": iter_result.metrics.iteration if iter_result.success else 0,
                    "iterative_complexity_reduction": (
                        iter_result.metrics.complexity_reduction if iter_result.success else 0.0
                    ),
                }

        performance, analysis_result = self._measure_performance(run_devirtualization)

        return BenchmarkResult(
            sample=sample,
            category=BenchmarkCategory.DEVIRTUALIZATION,
            performance=performance,
            accuracy=None,  # Devirtualization accuracy is more complex to measure
            analysis_result=analysis_result or {},
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            r2morph_version="2.0.0-phase2",
        )

    def benchmark_full_pipeline(self, sample: TestSample) -> BenchmarkResult:
        """
        Benchmark the full analysis pipeline on a sample.

        Args:
            sample: Test sample to analyze

        Returns:
            BenchmarkResult
        """
        from r2morph import Binary
        from r2morph.detection import AntiAnalysisBypass, ObfuscationDetector
        from r2morph.devirtualization import CFOSimplifier, IterativeSimplifier
        from r2morph.devirtualization.iterative_simplifier import SimplificationStrategy

        def run_full_pipeline() -> dict[str, Any]:
            with Binary(sample.file_path) as bin_obj:
                bin_obj.analyze()

                detector = ObfuscationDetector()
                detection_result = detector.analyze_binary(bin_obj)

                bypass_framework = AntiAnalysisBypass()
                detected_techniques = bypass_framework.detect_anti_analysis_techniques(bin_obj)
                bypass_applied = len(detected_techniques) > 0

                devirt_performed = False
                complexity_reduction = 0.0

                if detection_result.vm_detected or detection_result.control_flow_flattened:
                    cfo_simplifier = CFOSimplifier(bin_obj)
                    functions = bin_obj.get_functions()[:2]

                    for func in functions:
                        func_addr = func.get("offset", 0)
                        result = cfo_simplifier.simplify_control_flow(func_addr)
                        if result.success:
                            complexity_reduction += result.original_complexity - result.simplified_complexity

                    iterative_simplifier = IterativeSimplifier(bin_obj)
                    iter_result = iterative_simplifier.simplify(
                        strategy=SimplificationStrategy.CONSERVATIVE, max_iterations=2, timeout=20
                    )

                    if iter_result.success:
                        complexity_reduction += iter_result.metrics.complexity_reduction
                        devirt_performed = True

                return {
                    "detection_confidence": detection_result.confidence_score,
                    "packer_detected": (
                        detection_result.packer_detected.value if detection_result.packer_detected else None
                    ),
                    "vm_detected": detection_result.vm_detected,
                    "anti_analysis_bypass_applied": bypass_applied,
                    "devirtualization_performed": devirt_performed,
                    "total_complexity_reduction": complexity_reduction,
                    "obfuscation_techniques_count": len(detection_result.obfuscation_techniques),
                    "pipeline_completed": True,
                }

        performance, analysis_result = self._measure_performance(run_full_pipeline)

        accuracy = None
        if performance.success and analysis_result:
            expected = {
                "packer_detected": sample.expected_packer,
                "vm_protection": sample.expected_vm_protection,
                "anti_analysis": sample.expected_anti_analysis,
                "cfo_detected": sample.expected_cfo,
                "mba_detected": sample.expected_mba,
            }

            actual = {
                "packer_detected": analysis_result.get("packer_detected"),
                "vm_protection": analysis_result.get("vm_detected", False),
                "anti_analysis": analysis_result.get("anti_analysis_bypass_applied", False),
                "cfo_detected": analysis_result.get("devirtualization_performed", False),
                "mba_detected": False,  # Would need MBA-specific detection
            }

            accuracy = self._calculate_accuracy_metrics(expected, actual)

        return BenchmarkResult(
            sample=sample,
            category=BenchmarkCategory.FULL_PIPELINE,
            performance=performance,
            accuracy=accuracy,
            analysis_result=analysis_result or {},
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            r2morph_version="2.0.0-phase2",
        )

    def run_validation_suite(self, categories: list[BenchmarkCategory] | None = None) -> dict[str, Any]:
        """
        Run the complete validation suite.

        Args:
            categories: List of benchmark categories to run (all if None)

        Returns:
            Validation results summary
        """
        if categories is None:
            categories = [
                BenchmarkCategory.DETECTION,
                BenchmarkCategory.DEVIRTUALIZATION,
                BenchmarkCategory.FULL_PIPELINE,
            ]

        logger.info(f"Starting validation suite with {len(self.test_samples)} samples")
        logger.info(f"Categories: {[cat.value for cat in categories]}")

        results = []

        for sample in self.test_samples:
            if not sample.file_exists:
                logger.warning(f"Sample file not found: {sample.file_path}")
                continue

            if not sample.verify_hash():
                logger.warning(f"Sample hash verification failed: {sample.file_path}")
                continue

            logger.info(f"Testing sample: {sample.description}")

            for category in categories:
                try:
                    if category == BenchmarkCategory.DETECTION:
                        result = self.benchmark_detection(sample)
                    elif category == BenchmarkCategory.DEVIRTUALIZATION:
                        result = self.benchmark_devirtualization(sample)
                    elif category == BenchmarkCategory.FULL_PIPELINE:
                        result = self.benchmark_full_pipeline(sample)
                    else:
                        continue

                    results.append(result)
                    self.benchmark_results.append(result)

                    logger.info(
                        f"  {category.value}: {'PASS' if result.performance.success else 'FAIL'} "
                        f"({result.performance.execution_time:.2f}s)"
                    )

                except Exception as e:
                    logger.error(f"Benchmark failed for {sample.file_path} ({category.value}): {e}")

        summary = self._generate_validation_summary(results)

        logger.info("Validation suite completed")
        logger.info(f"Total tests: {summary['total_tests']}")
        logger.info(f"Success rate: {summary['success_rate']:.1%}")
        logger.info(f"Average execution time: {summary['avg_execution_time']:.2f}s")

        return summary

    def _generate_validation_summary(self, results: list[BenchmarkResult]) -> dict[str, Any]:
        """Generate a summary of validation results."""
        return generate_validation_summary(results)

    def export_results(self, output_path: str, format: str = "json") -> None:
        """
        Export benchmark results to file.

        Args:
            output_path: Output file path
            format: Export format ('json' or 'csv')
        """
        return export_benchmark_results(self.benchmark_results, output_path, format)

    def generate_report(self) -> str:
        """Generate a human-readable validation report."""
        return generate_benchmark_report(self.benchmark_results)
