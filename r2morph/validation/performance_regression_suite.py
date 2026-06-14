"""Suite orchestration for performance regression benchmarks."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from r2morph.validation.performance_regression_models import BenchmarkConfig

logger = logging.getLogger(__name__)


class PerformanceRegressionSuite:
    """Suite of performance regression tests."""

    def __init__(self, config: BenchmarkConfig | None = None) -> None:
        self.config = config or BenchmarkConfig()
        from r2morph.validation.performance_regression import PerformanceBenchmark

        self.benchmark = PerformanceBenchmark(self.config)
        self.test_binaries: list[tuple[Path, list[str], str]] = []

    def add_test(
        self,
        binary_path: Path,
        mutations: list[str],
        baseline_name: str,
    ) -> None:
        """Add a performance test."""
        self.test_binaries.append((binary_path, mutations, baseline_name))

    def run_all(self) -> dict[str, Any]:
        """Run all performance tests."""
        results: dict[str, Any] = {
            "passed": 0,
            "failed": 0,
            "regressions": [],
            "snapshots": [],
        }

        for binary_path, mutations, baseline_name in self.test_binaries:
            try:
                snapshot, regressions = self.benchmark.run_performance_test(
                    binary_path,
                    mutations,
                    baseline_name,
                )

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
                logger.error("Performance test failed for %s: %s", binary_path, e)
                results["failed"] += 1

        results["success_rate"] = (
            results["passed"] / (results["passed"] + results["failed"]) * 100
            if (results["passed"] + results["failed"]) > 0
            else 0
        )

        return results
