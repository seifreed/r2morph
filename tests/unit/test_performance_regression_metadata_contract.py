from __future__ import annotations

from r2morph.validation import performance_regression_metadata
from r2morph.validation.performance_regression import PerformanceBenchmark
from tests.utils.assertions import expect


def test_metadata_helpers_expose_expected_shape() -> None:
    expect(isinstance(performance_regression_metadata.get_git_hash(), str))
    expect(isinstance(performance_regression_metadata.get_cpu_count(), int))

    env = performance_regression_metadata.get_environment_info()
    expect(not ("python_version" not in env))
    expect(not ("platform" not in env))
    expect(not ("cpu_count" not in env))


def test_benchmark_metadata_methods_match_runtime_helpers() -> None:
    benchmark = PerformanceBenchmark()

    expect(
        (benchmark._get_git_hash(), benchmark._get_cpu_count(), benchmark._get_environment_info())
        == (
            performance_regression_metadata.get_git_hash(),
            performance_regression_metadata.get_cpu_count(),
            performance_regression_metadata.get_environment_info(),
        )
    )
