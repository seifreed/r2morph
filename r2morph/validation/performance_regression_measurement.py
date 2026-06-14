"""Measurement helpers for performance regression benchmarking."""

from __future__ import annotations

import gc
import logging
import time
import tracemalloc
from typing import Any

from r2morph.validation.performance_regression_models import BenchmarkConfig

logger = logging.getLogger(__name__)


def measure_execution_time(
    config: BenchmarkConfig,
    func: Any,
    *args: Any,
    **kwargs: Any,
) -> list[float]:
    """Measure execution time of a function over multiple runs."""
    times = []

    for i in range(config.warmup_runs):
        try:
            func(*args, **kwargs)
        except Exception as e:
            logger.warning("Warmup run %s failed: %s", i, e)

    for i in range(config.measured_runs):
        start = time.perf_counter()
        try:
            func(*args, **kwargs)
        except Exception as e:
            logger.error("Measured run %s failed: %s", i, e)
            continue
        end = time.perf_counter()
        times.append((end - start) * 1000)

    return times


def measure_memory_usage(
    func: Any,
    *args: Any,
    **kwargs: Any,
) -> dict[str, float]:
    """Measure memory usage of a function."""
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
        logger.error("Memory measurement failed: %s", e)
        return {
            "current_memory_mb": 0,
            "peak_memory_mb": 0,
        }
