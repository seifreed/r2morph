from pathlib import Path

from r2morph.performance import (
    PerformanceConfig,
    MemoryManager,
    ResultCache,
    ParallelAnalysisEngine,
    IncrementalAnalyzer,
    OptimizedAnalysisFramework,
    HAS_PSUTIL,
)


def test_result_cache_eviction_and_hit_ratio():
    cache = ResultCache(max_size=2)
    cache.set("a", 1)
    cache.set("b", 2)
    assert cache.get("a") == 1
    cache.set("c", 3)

    # "b" should be evicted because "a" was recently accessed
    assert cache.get("b") is None
    assert cache.get("a") == 1
    assert cache.get_hit_ratio() > 0


def test_memory_manager_chunk_size_bounds():
    config = PerformanceConfig(chunk_size=50)
    manager = MemoryManager(config)
    chunk_size = manager.get_optimal_chunk_size(total_items=1000)
    assert chunk_size >= 1
    if HAS_PSUTIL:
        assert chunk_size <= config.chunk_size
    else:
        assert chunk_size == config.chunk_size


def test_parallel_engine_cache_hits(tmp_path: Path):
    config = PerformanceConfig(enable_caching=True, enable_parallel=False)
    engine = ParallelAnalysisEngine(config)

    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(b"\x00\x01")

    def analysis_func(path: str):
        return {"value": Path(path).stat().st_size}

    first = engine._analyze_single_binary(str(test_file), analysis_func, "size")
    second = engine._analyze_single_binary(str(test_file), analysis_func, "size")

    assert first["success"] is True
    assert second["success"] is True
    assert engine.cache.hits == 1


def test_incremental_analyzer_state_roundtrip(tmp_path: Path):
    state_file = tmp_path / "state.json"
    analyzer = IncrementalAnalyzer(str(state_file))

    sample = tmp_path / "sample.txt"
    sample.write_text("hello")

    assert analyzer.has_file_changed(str(sample)) is True

    analyzer.update_file_state(str(sample), {"analysis": "ok"})
    assert analyzer.has_file_changed(str(sample)) is False
    assert analyzer.get_cached_result(str(sample)) == {"analysis": "ok"}

    sample.write_text("hello world")
    assert analyzer.has_file_changed(str(sample)) is True

    analyzer.cleanup_missing_files([str(sample)])
    analyzer.save()

    reloaded = IncrementalAnalyzer(str(state_file))
    assert str(sample) in reloaded.file_states


def test_optimized_framework_incremental_cache(tmp_path: Path):
    config = PerformanceConfig(enable_incremental=True, enable_parallel=False, chunk_size=10)
    state_file = tmp_path / "analysis_state.json"
    framework = OptimizedAnalysisFramework(config, incremental_state_file=str(state_file))

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00\x01")

    calls = {"count": 0}

    def analysis_func(path: str):
        calls["count"] += 1
        return {"value": Path(path).stat().st_size}

    results_first = framework.analyze_files([str(sample)], analysis_func, "size")
    assert calls["count"] == 1
    assert results_first[0]["success"] is True

    results_second = framework.analyze_files([str(sample)], analysis_func, "size")
    assert calls["count"] == 1
    assert len(results_second) == 1
