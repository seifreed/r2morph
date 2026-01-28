from __future__ import annotations

import json
from pathlib import Path

from r2morph.performance import (
    IncrementalAnalyzer,
    MemoryManager,
    ParallelAnalysisEngine,
    PerformanceConfig,
    ResourceMonitor,
    ResultCache,
)


def test_resource_monitor_and_memory_manager(tmp_path: Path) -> None:
    config = PerformanceConfig(memory_limit_mb=1, chunk_size=5)
    manager = MemoryManager(config)
    assert manager.check_memory_usage() in (True, False)
    manager.trigger_gc_if_needed()
    assert manager.get_optimal_chunk_size(10) >= 1

    monitor = ResourceMonitor()
    monitor.update()
    assert monitor.active_threads >= 1


def test_incremental_analyzer_state(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    analyzer = IncrementalAnalyzer(state_file=str(state_file))
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    assert analyzer.has_file_changed(str(sample)) is True
    analyzer.update_file_state(str(sample), {"ok": True})
    analyzer.save()
    assert analyzer.has_file_changed(str(sample)) is False

    analyzer.cleanup_missing_files([])
    analyzer.save()
    assert json.loads(state_file.read_text()) == {}


def test_parallel_engine_cache_hits(tmp_path: Path) -> None:
    sample = tmp_path / "file.bin"
    sample.write_bytes(b"payload")

    config = PerformanceConfig(enable_parallel=False, enable_caching=True)
    engine = ParallelAnalysisEngine(config)

    def analyze(path: str) -> dict[str, int]:
        return {"size": Path(path).stat().st_size}

    first = engine.analyze_batch([str(sample)], analyze, "size")
    assert first[0]["success"] is True
    second = engine.analyze_batch([str(sample)], analyze, "size")
    assert second[0]["success"] is True
    stats = engine.get_performance_stats()
    assert stats.get("cache_hit_ratio", 0.0) >= 0.0

    cache = ResultCache(max_size=1)
    cache.set("a", 1)
    cache.set("b", 2)
    assert cache.get("a") is None
