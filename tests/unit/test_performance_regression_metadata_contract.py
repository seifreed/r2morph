from __future__ import annotations

from r2morph.validation import performance_regression_metadata
from r2morph.validation.performance_regression import PerformanceBenchmark


def test_metadata_helpers_expose_expected_shape() -> None:
    assert isinstance(performance_regression_metadata.get_git_hash(), str)
    assert isinstance(performance_regression_metadata.get_cpu_count(), int)

    env = performance_regression_metadata.get_environment_info()
    assert "python_version" in env
    assert "platform" in env
    assert "cpu_count" in env


def test_benchmark_metadata_methods_match_runtime_helpers() -> None:
    benchmark = PerformanceBenchmark()

    assert (
        benchmark._get_git_hash(),
        benchmark._get_cpu_count(),
        benchmark._get_environment_info(),
    ) == (
        performance_regression_metadata.get_git_hash(),
        performance_regression_metadata.get_cpu_count(),
        performance_regression_metadata.get_environment_info(),
    )
