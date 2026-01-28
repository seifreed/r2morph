from pathlib import Path

import time

from r2morph.performance import (
    IncrementalAnalyzer,
    OptimizedAnalysisFramework,
    PerformanceConfig,
    ParallelAnalysisEngine,
    ResultCache,
)


def test_result_cache_hits_and_eviction():
    cache = ResultCache(max_size=2)
    cache.set("a", 1)
    cache.set("b", 2)
    time.sleep(0.01)
    assert cache.get("a") == 1  # make "b" least recently used
    time.sleep(0.01)

    cache.set("c", 3)
    assert "b" not in cache.cache
    assert cache.get("a") == 1
    assert cache.get("c") == 3
    assert cache.get_hit_ratio() > 0.0

    cache.clear()
    assert cache.cache == {}
    assert cache.get_hit_ratio() == 0.0


def test_incremental_analyzer_change_detection(tmp_path):
    state_file = tmp_path / "state.json"
    analyzer = IncrementalAnalyzer(state_file=str(state_file))

    sample_path = tmp_path / "sample.bin"
    sample_path.write_text("first")

    assert analyzer.has_file_changed(str(sample_path)) is True
    analyzer.update_file_state(str(sample_path), {"ok": True})
    analyzer.save()

    reloaded = IncrementalAnalyzer(state_file=str(state_file))
    assert reloaded.has_file_changed(str(sample_path)) is False
    assert reloaded.get_cached_result(str(sample_path))["ok"] is True

    sample_path.write_text("second")
    assert reloaded.has_file_changed(str(sample_path)) is True

    missing_path = tmp_path / "missing.bin"
    reloaded.cleanup_missing_files([str(sample_path), str(missing_path)])
    assert str(sample_path) in reloaded.file_states


def test_parallel_engine_sequential_and_cache(tmp_path):
    files = []
    for idx in range(2):
        file_path = tmp_path / f"file_{idx}.bin"
        file_path.write_text(f"data-{idx}")
        files.append(str(file_path))

    config = PerformanceConfig(
        enable_parallel=False,
        enable_caching=True,
        memory_limit_mb=1024,
        chunk_size=10,
    )
    engine = ParallelAnalysisEngine(config)

    def analyze_func(path: str):
        return {"size": Path(path).stat().st_size}

    first_results = engine.analyze_batch(files, analyze_func, "size")
    assert all(r["success"] for r in first_results)

    second_results = engine.analyze_batch(files, analyze_func, "size")
    assert all(r["success"] for r in second_results)
    assert engine.cache.get_hit_ratio() > 0.0


def test_optimized_analysis_framework_incremental(tmp_path):
    files = []
    for idx in range(2):
        file_path = tmp_path / f"payload_{idx}.bin"
        file_path.write_text(f"payload-{idx}")
        files.append(str(file_path))

    config = PerformanceConfig(
        enable_parallel=False,
        enable_caching=True,
        enable_incremental=True,
        memory_limit_mb=1024,
        chunk_size=10,
    )
    framework = OptimizedAnalysisFramework(config, incremental_state_file=str(tmp_path / "state.json"))

    def analyze_func(path: str):
        return {"value": Path(path).stat().st_size}

    results_first = framework.analyze_files(files, analyze_func, "payload")
    assert len(results_first) == 2

    results_second = framework.analyze_files(files, analyze_func, "payload")
    assert len(results_second) == 2
    stats = framework.get_comprehensive_stats()
    assert stats["incremental_files_tracked"] == 2
