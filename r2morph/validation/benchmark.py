"""
Real-world validation and benchmarking framework for r2morph.

This module provides comprehensive testing capabilities including:
- Performance benchmarking
- Accuracy metrics against known samples
- Regression testing
- Real-world validation scenarios
"""

import logging
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
from r2morph.validation.benchmark_runners import (
    benchmark_detection as run_detection_benchmark,
)
from r2morph.validation.benchmark_runners import (
    benchmark_devirtualization as run_devirtualization_benchmark,
)
from r2morph.validation.benchmark_runners import (
    benchmark_full_pipeline as run_full_pipeline_benchmark,
)
from r2morph.validation.benchmark_samples import (
    DEFAULT_TEST_SAMPLES,
    build_test_samples,
)
from r2morph.validation.benchmark_suite import run_validation_suite as run_validation_suite_impl
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
        self.test_samples = build_test_samples(self.test_data_dir, DEFAULT_TEST_SAMPLES)

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
        from r2morph.validation.benchmark_reporting_summary import calculate_percentile

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
        return run_detection_benchmark(
            sample,
            measure_performance=self._measure_performance,
            calculate_accuracy_metrics=self._calculate_accuracy_metrics,
        )

    def benchmark_devirtualization(self, sample: TestSample) -> BenchmarkResult:
        return run_devirtualization_benchmark(
            sample,
            measure_performance=self._measure_performance,
        )

    def benchmark_full_pipeline(self, sample: TestSample) -> BenchmarkResult:
        return run_full_pipeline_benchmark(
            sample,
            measure_performance=self._measure_performance,
            calculate_accuracy_metrics=self._calculate_accuracy_metrics,
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
        results, summary = run_validation_suite_impl(
            self.test_samples,
            categories,
            self.benchmark_detection,
            self.benchmark_devirtualization,
            self.benchmark_full_pipeline,
            self._generate_validation_summary,
            logger,
        )
        self.benchmark_results.extend(results)
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
