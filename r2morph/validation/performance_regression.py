"""
Performance regression testing framework.

Tracks performance metrics across code changes to detect regressions
and ensure mutation passes remain efficient.
"""

import gc
import json
import logging
import statistics
import time
import tracemalloc
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetric:
    """Single performance metric measurement."""

    name: str
    value: float
    unit: str
    timestamp: str
    sample_size: int = 1


@dataclass
class PerformanceSnapshot:
    """Snapshot of performance at a point in time."""

    commit_hash: str
    timestamp: str
    metrics: dict[str, float]
    environment: dict[str, str]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit_hash": self.commit_hash,
            "timestamp": self.timestamp,
            "metrics": self.metrics,
            "environment": self.environment,
            "metadata": self.metadata,
        }


@dataclass
class PerformanceRegression:
    """Detected performance regression."""

    metric_name: str
    baseline_value: float
    current_value: float
    threshold: float
    percentage_change: float
    severity: str  # "minor", "major", "critical"


@dataclass
class BenchmarkConfig:
    """Configuration for performance benchmarking."""

    warmup_runs: int = 3
    measured_runs: int = 10
    timeout_seconds: int = 300
    max_memory_mb: int = 1024
    regression_threshold_percent: float = 20.0
    critical_threshold_percent: float = 50.0


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
        import subprocess

        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()[:12]
        except Exception:
            return "unknown"

    def _get_environment_info(self) -> dict[str, str]:
        """Get environment information."""
        import platform
        import sys

        return {
            "python_version": sys.version.split()[0],
            "platform": platform.system(),
            "platform_version": platform.version(),
            "cpu_count": str(self._get_cpu_count()),
            "machine": platform.machine(),
        }

    def _get_cpu_count(self) -> int:
        """Get CPU count."""
        try:
            import os

            return os.cpu_count() or 1
        except Exception:
            return 1

    def measure_execution_time(
        self,
        func: Any,
        *args,
        **kwargs,
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
        times = []

        for i in range(self.config.warmup_runs):
            try:
                func(*args, **kwargs)
            except Exception as e:
                logger.warning(f"Warmup run {i} failed: {e}")

        for i in range(self.config.measured_runs):
            start = time.perf_counter()
            try:
                func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Measured run {i} failed: {e}")
                continue
            end = time.perf_counter()
            times.append((end - start) * 1000)

        return times

    def measure_memory_usage(
        self,
        func: Any,
        *args,
        **kwargs,
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
        gc.collect()

        tracemalloc.start()

        try:
            func(*args, **kwargs)

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            return {
                "current_memory_mb": current / (1024 * 1024),
                "peak_memory_mb": peak / (1024 * 1024),
            }
        except Exception as e:
            tracemalloc.stop()
            logger.error(f"Memory measurement failed: {e}")
            return {
                "current_memory_mb": 0,
                "peak_memory_mb": 0,
            }

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
        from r2morph import Binary
        from r2morph.mutations import (
            NopInsertionPass,
            InstructionSubstitutionPass,
            RegisterSubstitutionPass,
        )

        mutation_classes = {
            "nop": NopInsertionPass,
            "substitute": InstructionSubstitutionPass,
            "register": RegisterSubstitutionPass,
        }

        def run_mutation_pipeline() -> None:
            with Binary(binary_path) as binary:
                binary.analyze()
                for mutation_name in mutations:
                    mutation_class = mutation_classes.get(mutation_name.lower())
                    if mutation_class:
                        mutation = mutation_class()
                        mutation.apply(binary)

        exec_times = self.measure_execution_time(run_mutation_pipeline)
        memory_metrics = self.measure_memory_usage(run_mutation_pipeline)

        metrics = {
            "execution_time_ms_mean": statistics.mean(exec_times) if exec_times else 0,
            "execution_time_ms_median": statistics.median(exec_times) if exec_times else 0,
            "execution_time_ms_stdev": statistics.stdev(exec_times) if len(exec_times) > 1 else 0,
            "execution_time_ms_min": min(exec_times) if exec_times else 0,
            "execution_time_ms_max": max(exec_times) if exec_times else 0,
            "peak_memory_mb": memory_metrics["peak_memory_mb"],
            "current_memory_mb": memory_metrics["current_memory_mb"],
        }

        return PerformanceSnapshot(
            commit_hash=self._get_git_hash(),
            timestamp=datetime.now().isoformat(),
            metrics=metrics,
            environment=self._get_environment_info(),
            metadata={
                "binary": str(binary_path),
                "mutations": mutations,
                "runs": self.config.measured_runs,
            },
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
        baseline_file = self.baseline_dir / f"{baseline_name}.json"

        with open(baseline_file, "w") as f:
            json.dump(snapshot.to_dict(), f, indent=2)

        logger.info(f"Saved performance baseline: {baseline_file}")
        return baseline_file

    def load_baseline(self, baseline_name: str) -> PerformanceSnapshot | None:
        """
        Load performance baseline.

        Args:
            baseline_name: Name of the baseline

        Returns:
            PerformanceSnapshot or None if not found
        """
        baseline_file = self.baseline_dir / f"{baseline_name}.json"

        if not baseline_file.exists():
            logger.warning(f"Baseline not found: {baseline_file}")
            return None

        with open(baseline_file, "r") as f:
            data = json.load(f)

        return PerformanceSnapshot(
            commit_hash=data["commit_hash"],
            timestamp=data["timestamp"],
            metrics=data["metrics"],
            environment=data["environment"],
            metadata=data.get("metadata", {}),
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
        regressions = []

        for metric_name, baseline_value in baseline.metrics.items():
            if metric_name not in current.metrics:
                continue

            current_value = current.metrics[metric_name]

            if baseline_value == 0:
                continue

            percentage_change = ((current_value - baseline_value) / baseline_value) * 100

            if percentage_change > self.config.regression_threshold_percent:
                severity = "minor"
                if percentage_change > self.config.critical_threshold_percent:
                    severity = "critical"
                elif percentage_change > self.config.regression_threshold_percent * 2:
                    severity = "major"

                regressions.append(
                    PerformanceRegression(
                        metric_name=metric_name,
                        baseline_value=baseline_value,
                        current_value=current_value,
                        threshold=self.config.regression_threshold_percent,
                        percentage_change=percentage_change,
                        severity=severity,
                    )
                )

        return regressions

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


class PerformanceRegressionSuite:
    """
    Suite of performance regression tests.
    """

    def __init__(self, config: BenchmarkConfig | None = None) -> None:
        self.config = config or BenchmarkConfig()
        self.benchmark = PerformanceBenchmark(self.config)
        self.test_binaries: list[tuple[Path, list[str], str]] = []

    def add_test(
        self,
        binary_path: Path,
        mutations: list[str],
        baseline_name: str,
    ) -> None:
        """
        Add a performance test.

        Args:
            binary_path: Path to test binary
            mutations: List of mutation names
            baseline_name: Baseline name for comparison
        """
        self.test_binaries.append((binary_path, mutations, baseline_name))

    def run_all(self) -> dict[str, Any]:
        """
        Run all performance tests.

        Returns:
            Dictionary with results and any regressions
        """
        results = {
            "passed": 0,
            "failed": 0,
            "regressions": [],
            "snapshots": [],
        }

        for binary_path, mutations, baseline_name in self.test_binaries:
            try:
                snapshot, regressions = self.benchmark.run_performance_test(binary_path, mutations, baseline_name)

                results["snapshots"].append(snapshot.to_dict())

                if regressions:
                    results["failed"] += 1
                    for reg in regressions:
                        results["regressions"].append(
                            {
                                "binary": str(binary_path),
                                "metric": reg.metric_name,
                                "baseline": reg.baseline_value,
                                "current": reg.current_value,
                                "change": f"{reg.percentage_change:.1f}%",
                                "severity": reg.severity,
                            }
                        )
                else:
                    results["passed"] += 1

            except Exception as e:
                logger.error(f"Performance test failed for {binary_path}: {e}")
                results["failed"] += 1

        results["success_rate"] = (
            results["passed"] / (results["passed"] + results["failed"]) * 100
            if (results["passed"] + results["failed"]) > 0
            else 0
        )

        return results


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
