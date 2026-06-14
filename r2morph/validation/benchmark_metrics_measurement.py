"""Performance measurement helpers for benchmark execution."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from r2morph.validation.benchmark_types import PerformanceMetrics


def measure_performance(func: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[PerformanceMetrics, Any]:
    """Measure execution time, memory and CPU usage for a callable."""
    try:
        import psutil

        has_psutil = True
    except ImportError:
        psutil = None
        has_psutil = False

    start_memory: float = 0
    peak_memory: float = 0
    cpu_percent: float = 0
    process = psutil.Process() if has_psutil else None

    if process is not None:
        start_memory = process.memory_info().rss / 1024 / 1024

    start_time = time.time()
    success = True
    error_message = None

    try:
        result = func(*args, **kwargs)
        if process is not None:
            peak_memory = process.memory_info().rss / 1024 / 1024
            cpu_percent = process.cpu_percent()
    except Exception as exc:
        success = False
        error_message = str(exc)
        result = None

    execution_time = time.time() - start_time
    if process is not None:
        memory_usage = process.memory_info().rss / 1024 / 1024 - start_memory
    else:
        memory_usage = 0
        peak_memory = 0
        cpu_percent = 0

    return (
        PerformanceMetrics(
            execution_time=execution_time,
            memory_usage_mb=memory_usage,
            cpu_usage_percent=cpu_percent,
            peak_memory_mb=peak_memory,
            success=success,
            error_message=error_message,
        ),
        result,
    )
