"""Pure benchmark metric helpers."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from r2morph.validation.benchmark_types import AccuracyMetrics, PerformanceMetrics


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


def calculate_accuracy_metrics(expected: dict[str, Any], actual: dict[str, Any]) -> AccuracyMetrics:
    """Compute accuracy metrics from expected and actual benchmark results."""
    fields = ["packer_detected", "vm_protection", "anti_analysis", "cfo_detected", "mba_detected"]
    tp = fp = tn = fn = 0

    for field in fields:
        exp_val = expected.get(field, False)
        act_val = actual.get(field, False)
        if exp_val and act_val:
            tp += 1
        elif not exp_val and act_val:
            fp += 1
        elif not exp_val and not act_val:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

    return AccuracyMetrics(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        accuracy=accuracy,
    )


__all__ = ["measure_performance", "calculate_accuracy_metrics"]
