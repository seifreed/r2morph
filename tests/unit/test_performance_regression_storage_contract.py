from __future__ import annotations

from pathlib import Path

from r2morph.validation.performance_regression import PerformanceBenchmark
from r2morph.validation.performance_regression_models import PerformanceSnapshot
from r2morph.validation.performance_regression_storage import (
    load_baseline_snapshot,
    save_baseline_snapshot,
)
from tests.utils.assertions import expect


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

    expect(baseline_file == tmp_path / "baseline.json")
    expect(baseline_file.exists())

    loaded = load_baseline_snapshot(
        baseline_dir=tmp_path,
        baseline_name="baseline",
    )

    expect(loaded is not None)
    expect(loaded.commit_hash == snapshot.commit_hash)
    expect(loaded.timestamp == snapshot.timestamp)
    expect(loaded.metrics == snapshot.metrics)
    expect(loaded.environment == snapshot.environment)
    expect(loaded.metadata == snapshot.metadata)


def test_benchmark_delegates_baseline_storage(tmp_path: Path) -> None:
    benchmark = PerformanceBenchmark()
    benchmark.baseline_dir = tmp_path
    snapshot = _make_snapshot()

    saved = benchmark.save_baseline(snapshot, "delegated")
    loaded = benchmark.load_baseline("delegated")

    expect(saved == tmp_path / "delegated.json")
    expect(loaded is not None)
    expect(loaded.commit_hash == snapshot.commit_hash)
    expect(loaded.metrics == snapshot.metrics)
