from pathlib import Path

from r2morph.performance import (
    PerformanceConfig,
    MemoryManager,
    ResultCache,
    ParallelAnalysisEngine,
    IncrementalAnalyzer,
    OptimizedAnalysisFramework,
    create_detection_analysis_func,
)


def test_memory_manager_and_cache(tmp_path: Path):
    config = PerformanceConfig(memory_limit_mb=8192)
    mem = MemoryManager(config)

    assert mem.check_memory_usage() in {True, False}
    mem.trigger_gc_if_needed()

    cache = ResultCache(max_size=2)
    cache.set("a", 1)
    cache.set("b", 2)
    assert cache.get("a") == 1
    cache.set("c", 3)
    assert cache.get("b") is None or cache.get("c") == 3

    ratio = cache.get_hit_ratio()
    assert 0.0 <= ratio <= 1.0

    cache.clear()
    assert cache.get_hit_ratio() == 0.0


def test_parallel_engine_analysis_path(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")

    def analyze_stub(path: str) -> dict:
        return {"binary_path": path, "ok": True}

    config = PerformanceConfig(enable_caching=True, enable_parallel=False)
    engine = ParallelAnalysisEngine(config)

    result = engine._analyze_single_binary(str(binary_path), analyze_stub, "stub")
    assert result["ok"]

    batch = engine.analyze_batch([str(binary_path)], analyze_stub, "stub")
    assert isinstance(batch, list)
    assert batch[0]["binary_path"] == str(binary_path)

    stats = engine.get_performance_stats()
    assert "cache_hit_ratio" in stats


def test_incremental_analyzer_state(tmp_path: Path):
    state_file = tmp_path / "state.json"
    analyzer = IncrementalAnalyzer(str(state_file))

    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"abc")

    assert analyzer.has_file_changed(str(file_path))
    analyzer.update_file_state(str(file_path), {"result": True})

    assert analyzer.get_cached_result(str(file_path)) is not None
    assert not analyzer.has_file_changed(str(file_path))

    analyzer.cleanup_missing_files([str(file_path)])
    analyzer.save()


def test_optimized_framework_detection(tmp_path: Path):
    config = PerformanceConfig(enable_parallel=False, enable_incremental=True)
    framework = OptimizedAnalysisFramework(config, incremental_state_file=str(tmp_path / "inc.json"))
    detection_func = create_detection_analysis_func()

    binary_path = Path("dataset/elf_x86_64")
    results = framework.analyze_files([str(binary_path)], detection_func, "detection")
    assert results
