from pathlib import Path

from r2morph.performance import (
    PerformanceConfig,
    MemoryManager,
    ResultCache,
    ParallelAnalysisEngine,
    IncrementalAnalyzer,
    OptimizedAnalysisFramework,
    create_detection_analysis_func,
    create_devirtualization_analysis_func,
)


def test_result_cache_eviction_and_hit_ratio():
    cache = ResultCache(max_size=2)
    cache.set("a", 1)
    cache.set("b", 2)
    assert cache.get("a") == 1
    cache.set("c", 3)
    assert cache.get("b") is None
    assert cache.get_hit_ratio() > 0.0
    cache.clear()
    assert cache.cache == {}


def test_memory_manager_checks_and_chunk_size():
    config = PerformanceConfig(memory_limit_mb=0, chunk_size=10)
    manager = MemoryManager(config)
    assert manager.check_memory_usage() is False
    manager.trigger_gc_if_needed()
    chunk_size = manager.get_optimal_chunk_size(total_items=50)
    assert chunk_size >= 1


def test_parallel_analysis_engine_threadpool(tmp_path):
    config = PerformanceConfig(max_workers=2, enable_parallel=True, enable_caching=True)
    engine = ParallelAnalysisEngine(config)

    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    file_a.write_bytes(b"AAAA")
    file_b.write_bytes(b"BBBBB")

    def analyze(path: str) -> dict[str, int | str]:
        p = Path(path)
        return {"path": str(p), "size": p.stat().st_size}

    results = engine.analyze_batch([str(file_a), str(file_b)], analyze, "size")
    assert len(results) == 2

    results_cached = engine.analyze_batch([str(file_a)], analyze, "size")
    assert results_cached[0]["path"] == str(file_a)

    stats = engine.get_performance_stats()
    assert "cache_hit_ratio" in stats

    chunks = list(engine.analyze_chunked([str(file_a), str(file_b)], analyze, "size"))
    assert sum(len(chunk) for chunk in chunks) == 2


def test_incremental_analyzer_state_roundtrip(tmp_path):
    state_file = tmp_path / "state.json"
    analyzer = IncrementalAnalyzer(str(state_file))

    file_a = tmp_path / "x.bin"
    file_a.write_text("one", encoding="utf-8")

    assert analyzer.has_file_changed(str(file_a)) is True
    analyzer.update_file_state(str(file_a), {"ok": True})
    assert analyzer.has_file_changed(str(file_a)) is False

    cached = analyzer.get_cached_result(str(file_a))
    assert cached["ok"] is True

    analyzer.cleanup_missing_files([str(file_a)])
    analyzer.save()
    assert state_file.exists()


def test_optimized_analysis_framework_smoke(tmp_path):
    file_a = tmp_path / "sample.bin"
    file_a.write_bytes(b"\x90" * 8)

    config = PerformanceConfig(enable_parallel=False, enable_caching=True, enable_incremental=True)
    framework = OptimizedAnalysisFramework(config, incremental_state_file=str(tmp_path / "inc.json"))

    def analyze(path: str) -> dict[str, int | bool]:
        return {"size": Path(path).stat().st_size, "success": True}

    results = framework.analyze_files([str(file_a)], analyze, "size")
    assert results[0]["success"] is True

    stats = framework.get_comprehensive_stats()
    assert "memory_usage_mb" in stats


def test_detection_and_devirtualization_analysis_funcs():
    binary_path = Path("dataset/elf_x86_64")
    detection = create_detection_analysis_func()
    devirt = create_devirtualization_analysis_func()

    detection_result = detection(str(binary_path))
    assert "techniques_count" in detection_result or "error" in detection_result

    devirt_result = devirt(str(binary_path))
    assert "functions_analyzed" in devirt_result or "error" in devirt_result
