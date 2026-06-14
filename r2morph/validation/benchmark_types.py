"""Compatibility wrapper for benchmark model definitions."""

from r2morph.validation import benchmark_models as _benchmark_models

AccuracyMetrics = _benchmark_models.AccuracyMetrics
BenchmarkCategory = _benchmark_models.BenchmarkCategory
BenchmarkResult = _benchmark_models.BenchmarkResult
PerformanceMetrics = _benchmark_models.PerformanceMetrics
TestSample = _benchmark_models.TestSample
TestSeverity = _benchmark_models.TestSeverity

__all__ = [
    "AccuracyMetrics",
    "BenchmarkCategory",
    "BenchmarkResult",
    "PerformanceMetrics",
    "TestSample",
    "TestSeverity",
]
