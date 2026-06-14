"""
Performance regression testing framework.

Tracks performance metrics across code changes to detect regressions
and ensure mutation passes remain efficient.
"""

from datetime import datetime
from importlib import import_module
from pathlib import Path
from typing import Any

from r2morph.validation import (
    performance_regression_comparison,
    performance_regression_measurement,
    performance_regression_metadata,
)
from r2morph.validation.performance_regression_execution import (
    build_mutation_class_map,
    build_performance_snapshot,
    create_mutation_pipeline,
)
from r2morph.validation.performance_regression_models import (
    BenchmarkConfig,
    PerformanceMetric,
    PerformanceRegression,
    PerformanceSnapshot,
)
from r2morph.validation.performance_regression_storage import (
    load_baseline_snapshot,
    save_baseline_snapshot,
)


class PerformanceBenchmark:
    """
    Performance benchmarking for mutation passes.

    Measures execution time, memory usage, and other metrics
    to detect performance regressions.
    """

    def __init__(self, config: BenchmarkConfig | None = None) -> None:
        self.config = config or BenchmarkConfig()
        self.baseline_dir = Path("performance_baselines")
        self.baseline_dir.mkdir(exist_ok=True)

    def _get_git_hash(self) -> str:
        """Get current git commit hash."""
        return performance_regression_metadata.get_git_hash()

    def _get_environment_info(self) -> dict[str, str]:
        """Get environment information."""
        return performance_regression_metadata.get_environment_info()

    def _get_cpu_count(self) -> int:
        """Get CPU count."""
        return performance_regression_metadata.get_cpu_count()

    def measure_execution_time(
        self,
        func: Any,
        *args: Any,
        **kwargs: Any,
    ) -> list[float]:
        """
        Measure execution time of a function over multiple runs.

        Args:
            func: Function to measure
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            List of execution times in milliseconds
        """
        return performance_regression_measurement.measure_execution_time(
            self.config,
            func,
            *args,
            **kwargs,
        )

    def measure_memory_usage(
        self,
        func: Any,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, float]:
        """
        Measure memory usage of a function.

        Args:
            func: Function to measure
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Dictionary with memory metrics in MB
        """
        return performance_regression_measurement.measure_memory_usage(
            func,
            *args,
            **kwargs,
        )

    def benchmark_binary(
        self,
        binary_path: Path,
        mutations: list[str],
        test_cases: list[dict[str, Any]] | None = None,
    ) -> PerformanceSnapshot:
        """
        Benchmark mutation pass on a binary.

        Args:
            binary_path: Path to test binary
            mutations: List of mutation pass names
            test_cases: Optional test cases for validation

        Returns:
            PerformanceSnapshot with metrics
        """
        mutation_classes = build_mutation_class_map()
        run_mutation_pipeline = create_mutation_pipeline(binary_path, mutations, mutation_classes)

        exec_times = self.measure_execution_time(run_mutation_pipeline)
        memory_metrics = self.measure_memory_usage(run_mutation_pipeline)
        return build_performance_snapshot(
            config=self.config,
            binary_path=binary_path,
            mutations=mutations,
            exec_times=exec_times,
            memory_metrics=memory_metrics,
            commit_hash=self._get_git_hash(),
            environment=self._get_environment_info(),
            timestamp=datetime.now().isoformat(),
        )

    def save_baseline(
        self,
        snapshot: PerformanceSnapshot,
        baseline_name: str,
    ) -> Path:
        """
        Save performance baseline.

        Args:
            snapshot: Performance snapshot
            baseline_name: Name for the baseline

        Returns:
            Path to saved baseline
        """
        return save_baseline_snapshot(
            snapshot=snapshot,
            baseline_dir=self.baseline_dir,
            baseline_name=baseline_name,
        )

    def load_baseline(self, baseline_name: str) -> PerformanceSnapshot | None:
        """
        Load performance baseline.

        Args:
            baseline_name: Name of the baseline

        Returns:
            PerformanceSnapshot or None if not found
        """
        return load_baseline_snapshot(
            baseline_dir=self.baseline_dir,
            baseline_name=baseline_name,
        )

    def compare_against_baseline(
        self,
        current: PerformanceSnapshot,
        baseline: PerformanceSnapshot,
    ) -> list[PerformanceRegression]:
        """
        Compare current performance against baseline.

        Args:
            current: Current performance snapshot
            baseline: Baseline performance snapshot

        Returns:
            List of detected regressions
        """
        return performance_regression_comparison.compare_against_baseline(
            current,
            baseline,
            self.config.regression_threshold_percent,
            self.config.critical_threshold_percent,
        )

    def run_performance_test(
        self,
        binary_path: Path,
        mutations: list[str],
        baseline_name: str | None = None,
    ) -> tuple[PerformanceSnapshot, list[PerformanceRegression]]:
        """
        Run performance test and optionally compare against baseline.

        Args:
            binary_path: Path to test binary
            mutations: List of mutation pass names
            baseline_name: Optional baseline name to compare against

        Returns:
            Tuple of (current_snapshot, regressions)
        """
        current = self.benchmark_binary(binary_path, mutations)

        regressions = []
        if baseline_name:
            baseline = self.load_baseline(baseline_name)
            if baseline:
                regressions = self.compare_against_baseline(current, baseline)

        return current, regressions


def create_benchmark(
    warmup_runs: int = 3,
    measured_runs: int = 10,
    regression_threshold: float = 20.0,
) -> PerformanceBenchmark:
    """
    Create a configured performance benchmark.

    Args:
        warmup_runs: Number of warmup runs
        measured_runs: Number of measured runs
        regression_threshold: Percentage threshold for regression detection

    Returns:
        PerformanceBenchmark instance
    """
    config = BenchmarkConfig(
        warmup_runs=warmup_runs,
        measured_runs=measured_runs,
        regression_threshold_percent=regression_threshold,
    )
    return PerformanceBenchmark(config)
PerformanceRegressionSuite = import_module(
    "r2morph.validation.performance_regression_suite",
).PerformanceRegressionSuite


__all__ = [
    "PerformanceMetric",
    "PerformanceSnapshot",
    "PerformanceRegression",
    "BenchmarkConfig",
    "PerformanceBenchmark",
    "PerformanceRegressionSuite",
    "create_benchmark",
]
