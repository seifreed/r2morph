"""Execution helper for the validation benchmark suite."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from r2morph.validation.benchmark_types import BenchmarkCategory, BenchmarkResult, TestSample


def run_validation_suite(
    test_samples: list[TestSample],
    categories: list[BenchmarkCategory],
    benchmark_detection: Callable[[TestSample], BenchmarkResult],
    benchmark_devirtualization: Callable[[TestSample], BenchmarkResult],
    benchmark_full_pipeline: Callable[[TestSample], BenchmarkResult],
    generate_summary: Callable[[list[BenchmarkResult]], dict[str, Any]],
    logger: logging.Logger,
) -> tuple[list[BenchmarkResult], dict[str, Any]]:
    """Run a validation benchmark suite over the provided samples."""
    results: list[BenchmarkResult] = []

    logger.info("Starting validation suite with %s samples", len(test_samples))
    logger.info("Categories: %s", [cat.value for cat in categories])

    for sample in test_samples:
        if not sample.file_exists:
            logger.warning("Sample file not found: %s", sample.file_path)
            continue

        if not sample.verify_hash():
            logger.warning("Sample hash verification failed: %s", sample.file_path)
            continue

        logger.info("Testing sample: %s", sample.description)

        for category in categories:
            try:
                if category == BenchmarkCategory.DETECTION:
                    result = benchmark_detection(sample)
                elif category == BenchmarkCategory.DEVIRTUALIZATION:
                    result = benchmark_devirtualization(sample)
                elif category == BenchmarkCategory.FULL_PIPELINE:
                    result = benchmark_full_pipeline(sample)
                else:
                    continue

                results.append(result)

                logger.info(
                    "  %s: %s (%0.2fs)",
                    category.value,
                    "PASS" if result.performance.success else "FAIL",
                    result.performance.execution_time,
                )
            except Exception as exc:
                logger.error("Benchmark failed for %s (%s): %s", sample.file_path, category.value, exc)

    summary = generate_summary(results)

    logger.info("Validation suite completed")
    logger.info("Total tests: %s", summary["total_tests"])
    logger.info("Success rate: %0.1f%%", summary["success_rate"] * 100)
    logger.info("Average execution time: %0.2fs", summary["avg_execution_time"])

    return results, summary
