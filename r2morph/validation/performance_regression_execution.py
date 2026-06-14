"""Execution helpers for performance regression benchmarking."""

from __future__ import annotations

import statistics
from collections.abc import Callable
from pathlib import Path
from typing import Any

from r2morph.validation.performance_regression_models import BenchmarkConfig, PerformanceSnapshot


def build_mutation_class_map() -> dict[str, Any]:
    """Build the mutation class lookup used by the benchmark pipeline."""

    from r2morph.mutations import (
        InstructionSubstitutionPass,
        NopInsertionPass,
        RegisterSubstitutionPass,
    )

    return {
        "nop": NopInsertionPass,
        "substitute": InstructionSubstitutionPass,
        "register": RegisterSubstitutionPass,
    }


def create_mutation_pipeline(
    binary_path: Path,
    mutations: list[str],
    mutation_classes: dict[str, Any],
) -> Callable[[], None]:
    """Create a callable that runs the configured mutation pipeline."""

    def run_mutation_pipeline() -> None:
        from r2morph import Binary

        with Binary(binary_path) as binary:
            binary.analyze()
            for mutation_name in mutations:
                mutation_class = mutation_classes.get(mutation_name.lower())
                if mutation_class:
                    mutation = mutation_class()
                    mutation.apply(binary)

    return run_mutation_pipeline


def build_performance_metrics(
    exec_times: list[float],
    memory_metrics: dict[str, float],
) -> dict[str, float]:
    """Build the benchmark metrics payload."""

    return {
        "execution_time_ms_mean": statistics.mean(exec_times) if exec_times else 0,
        "execution_time_ms_median": statistics.median(exec_times) if exec_times else 0,
        "execution_time_ms_stdev": statistics.stdev(exec_times) if len(exec_times) > 1 else 0,
        "execution_time_ms_min": min(exec_times) if exec_times else 0,
        "execution_time_ms_max": max(exec_times) if exec_times else 0,
        "peak_memory_mb": memory_metrics["peak_memory_mb"],
        "current_memory_mb": memory_metrics["current_memory_mb"],
    }


def build_performance_snapshot(
    *,
    config: BenchmarkConfig,
    binary_path: Path,
    mutations: list[str],
    exec_times: list[float],
    memory_metrics: dict[str, float],
    commit_hash: str,
    environment: dict[str, str],
    timestamp: str,
) -> PerformanceSnapshot:
    """Build a performance snapshot from measured execution data."""

    metrics = build_performance_metrics(exec_times, memory_metrics)
    return PerformanceSnapshot(
        commit_hash=commit_hash,
        timestamp=timestamp,
        metrics=metrics,
        environment=environment,
        metadata={
            "binary": str(binary_path),
            "mutations": mutations,
            "runs": config.measured_runs,
        },
    )
