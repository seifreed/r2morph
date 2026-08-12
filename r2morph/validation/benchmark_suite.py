"""Execution helper for the validation benchmark suite."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from r2morph.validation.benchmark_types import BenchmarkCategory, BenchmarkResult, TestSample


@dataclass(frozen=True)
class ValidationSuiteActions:
    """Benchmark operations and reporting collaborators for a suite run."""

    detection: Callable[[TestSample], BenchmarkResult]
    devirtualization: Callable[[TestSample], BenchmarkResult]
    full_pipeline: Callable[[TestSample], BenchmarkResult]
    summarize: Callable[[list[BenchmarkResult]], dict[str, Any]]
    logger: logging.Logger


def run_validation_suite(
    test_samples: list[TestSample],
    categories: list[BenchmarkCategory],
    actions: ValidationSuiteActions,
) -> tuple[list[BenchmarkResult], dict[str, Any]]:
    """Run a validation benchmark suite over the provided samples."""
    results: list[BenchmarkResult] = []

    actions.logger.info("Starting validation suite with %s samples", len(test_samples))
    actions.logger.info("Categories: %s", [cat.value for cat in categories])

    for sample in test_samples:
        if not sample.file_exists:
            actions.logger.warning("Sample file not found: %s", sample.file_path)
            continue

        if not sample.verify_hash():
            actions.logger.warning("Sample hash verification failed: %s", sample.file_path)
            continue

        actions.logger.info("Testing sample: %s", sample.description)

        for category in categories:
            try:
                if category == BenchmarkCategory.DETECTION:
                    result = actions.detection(sample)
                elif category == BenchmarkCategory.DEVIRTUALIZATION:
                    result = actions.devirtualization(sample)
                elif category == BenchmarkCategory.FULL_PIPELINE:
                    result = actions.full_pipeline(sample)
                else:
                    continue

                results.append(result)

                actions.logger.info(
                    "  %s: %s (%0.2fs)",
                    category.value,
                    "PASS" if result.performance.success else "FAIL",
                    result.performance.execution_time,
                )
            except Exception as exc:
                actions.logger.error("Benchmark failed for %s (%s): %s", sample.file_path, category.value, exc)

    summary = actions.summarize(results)

    actions.logger.info("Validation suite completed")
    actions.logger.info("Total tests: %s", summary["total_tests"])
    actions.logger.info("Success rate: %0.1f%%", summary["success_rate"] * 100)
    actions.logger.info("Average execution time: %0.2fs", summary["avg_execution_time"])

    return results, summary
