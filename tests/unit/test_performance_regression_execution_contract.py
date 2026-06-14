from pathlib import Path

from r2morph.validation.performance_regression_execution import (
    build_mutation_class_map,
    build_performance_metrics,
    build_performance_snapshot,
)
from r2morph.validation.performance_regression_models import BenchmarkConfig


def test_build_mutation_class_map_contains_expected_passes() -> None:
    mutation_classes = build_mutation_class_map()

    assert {"nop", "substitute", "register"}.issubset(mutation_classes)


def test_build_performance_metrics_calculates_summary_stats() -> None:
    metrics = build_performance_metrics([1.0, 3.0, 5.0], {"peak_memory_mb": 8.0, "current_memory_mb": 4.0})

    assert metrics == {
        "execution_time_ms_mean": 3.0,
        "execution_time_ms_median": 3.0,
        "execution_time_ms_stdev": 2.0,
        "execution_time_ms_min": 1.0,
        "execution_time_ms_max": 5.0,
        "peak_memory_mb": 8.0,
        "current_memory_mb": 4.0,
    }


def test_build_performance_snapshot_preserves_metadata() -> None:
    snapshot = build_performance_snapshot(
        config=BenchmarkConfig(measured_runs=7),
        binary_path=Path("/tmp/demo.bin"),
        mutations=["nop", "register"],
        exec_times=[2.0, 4.0],
        memory_metrics={"peak_memory_mb": 9.0, "current_memory_mb": 3.0},
        commit_hash="deadbeef",
        environment={"platform": "test"},
        timestamp="2024-01-01T00:00:00",
    )

    assert snapshot.commit_hash == "deadbeef"
    assert snapshot.timestamp == "2024-01-01T00:00:00"
    assert snapshot.metrics["execution_time_ms_mean"] == 3.0
    assert snapshot.metadata == {
        "binary": "/tmp/demo.bin",
        "mutations": ["nop", "register"],
        "runs": 7,
    }
