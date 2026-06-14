"""Compatibility wrapper for benchmark runner functions."""

from r2morph.validation.benchmark_runners_detection import benchmark_detection
from r2morph.validation.benchmark_runners_devirtualization import benchmark_devirtualization
from r2morph.validation.benchmark_runners_full_pipeline import benchmark_full_pipeline

__all__ = ["benchmark_detection", "benchmark_devirtualization", "benchmark_full_pipeline"]
