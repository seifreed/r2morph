"""Execution helpers for performance regression benchmarking."""

from __future__ import annotations

import statistics
from collections.abc import Callable
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass


def build_mutation_class_map() -> dict[str, Any]:
    """Build the mutation class lookup used by the benchmark pipeline."""

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
