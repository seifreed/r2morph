from __future__ import annotations

from pathlib import Path

from r2morph.validation.performance_regression import PerformanceBenchmark
from r2morph.validation.performance_regression_models import PerformanceSnapshot
from r2morph.validation.performance_regression_storage import (
    load_baseline_snapshot,
    save_baseline_snapshot,
)


def _make_snapshot() -> PerformanceSnapshot:
    return PerformanceSnapshot(
        commit_hash="abc123",
        timestamp="2024-01-01T00:00:00",
        metrics={
            "execution_time_ms_mean": 100.5,
            "peak_memory_mb": 50.2,
        },
        environment={"platform": "linux"},
        metadata={"test": "value"},
    )


def test_storage_round_trip(tmp_path: Path) -> None:
    snapshot = _make_snapshot()

    baseline_file = save_baseline_snapshot(
        snapshot=snapshot,
        baseline_dir=tmp_path,
        baseline_name="baseline",
    )

    assert baseline_file == tmp_path / "baseline.json"
    assert baseline_file.exists()

    loaded = load_baseline_snapshot(
        baseline_dir=tmp_path,
        baseline_name="baseline",
    )

    assert loaded is not None
    assert loaded.commit_hash == snapshot.commit_hash
    assert loaded.timestamp == snapshot.timestamp
    assert loaded.metrics == snapshot.metrics
    assert loaded.environment == snapshot.environment
    assert loaded.metadata == snapshot.metadata


def test_benchmark_delegates_baseline_storage(tmp_path: Path) -> None:
    benchmark = PerformanceBenchmark()
    benchmark.baseline_dir = tmp_path
    snapshot = _make_snapshot()

    saved = benchmark.save_baseline(snapshot, "delegated")
    loaded = benchmark.load_baseline("delegated")

    assert saved == tmp_path / "delegated.json"
    assert loaded is not None
    assert loaded.commit_hash == snapshot.commit_hash
    assert loaded.metrics == snapshot.metrics
