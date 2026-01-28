from __future__ import annotations

from pathlib import Path

from r2morph.performance import (
    IncrementalAnalyzer,
    OptimizedAnalysisFramework,
    ParallelAnalysisEngine,
    PerformanceConfig,
    ResultCache,
)


def test_result_cache_and_incremental(tmp_path: Path) -> None:
    cache = ResultCache(max_size=2)
    assert cache.get("a") is None
    cache.set("a", 1)
    cache.set("b", 2)
    cache.set("c", 3)
    assert cache.get("a") is None
    assert cache.get("b") == 2
    assert cache.get("c") == 3

    state_file = tmp_path / "state.json"
    analyzer = IncrementalAnalyzer(state_file=str(state_file))
    sample = tmp_path / "file.bin"
    sample.write_bytes(b"data")
    assert analyzer.has_file_changed(str(sample)) is True

    analyzer.update_file_state(str(sample), {"ok": True})
    analyzer.save()
    assert analyzer.has_file_changed(str(sample)) is False
    assert analyzer.get_cached_result(str(sample)) == {"ok": True}


def test_parallel_engine_and_framework(tmp_path: Path) -> None:
    sample = tmp_path / "file.bin"
    sample.write_bytes(b"data")

    config = PerformanceConfig(enable_parallel=False, enable_caching=True, chunk_size=10)
    engine = ParallelAnalysisEngine(config)

    def analyze(path: str) -> dict[str, int]:
        return {"size": Path(path).stat().st_size}

    results = engine.analyze_batch([str(sample)], analyze, "size")
    assert results[0]["success"] is True
    assert results[0]["size"] == 4

    framework = OptimizedAnalysisFramework(config, incremental_state_file=str(tmp_path / "inc.json"))
    framework_results = framework.analyze_files([str(sample)], analyze, "size")
    assert framework_results
    stats = framework.get_comprehensive_stats()
    assert "memory_usage_mb" in stats
