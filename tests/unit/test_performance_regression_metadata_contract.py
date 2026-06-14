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


def test_benchmark_metadata_methods_delegate(monkeypatch) -> None:
    benchmark = PerformanceBenchmark()

    monkeypatch.setattr(
        performance_regression_metadata,
        "get_git_hash",
        lambda: "deadbeef",
    )
    monkeypatch.setattr(
        performance_regression_metadata,
        "get_cpu_count",
        lambda: 42,
    )
    monkeypatch.setattr(
        performance_regression_metadata,
        "get_environment_info",
        lambda: {"python_version": "3.14", "platform": "test", "cpu_count": "42"},
    )

    assert benchmark._get_git_hash() == "deadbeef"
    assert benchmark._get_cpu_count() == 42
    assert benchmark._get_environment_info() == {
        "python_version": "3.14",
        "platform": "test",
        "cpu_count": "42",
    }
