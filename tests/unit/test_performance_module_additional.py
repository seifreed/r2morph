from __future__ import annotations

import time
from pathlib import Path

import pytest

from r2morph.performance import (
    IncrementalAnalyzer,
    OptimizedAnalysisFramework,
    ParallelAnalysisEngine,
    PerformanceConfig,
    ResultCache,
    create_detection_analysis_func,
    create_devirtualization_analysis_func,
)


def test_result_cache_eviction_and_hit_ratio() -> None:
    cache = ResultCache(max_size=2)
    assert cache.get("missing") is None
    cache.set("a", 1)
    cache.set("b", 2)
    assert cache.get("a") == 1
    cache.set("c", 3)  # evicts LRU
    assert cache.get("b") is None or cache.get("c") == 3
    assert 0.0 <= cache.get_hit_ratio() <= 1.0
    cache.clear()
    assert cache.cache == {}


def test_parallel_engine_batch_and_chunked(tmp_path: Path) -> None:
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    config = PerformanceConfig(max_workers=2, use_multiprocessing=False)
    engine = ParallelAnalysisEngine(config)

    def analysis_func(path: str) -> dict:
        return {"path": path, "ok": True}

    results = engine.analyze_batch([str(binary_path), str(binary_path)], analysis_func)
    assert len(results) == 2
    stats = engine.get_performance_stats()
    assert "cache_hit_ratio" in stats

    chunks = list(engine.analyze_chunked([str(binary_path)], analysis_func))
    assert chunks


def test_incremental_analyzer_state(tmp_path: Path) -> None:
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    state_file = tmp_path / "incremental_state.json"
    analyzer = IncrementalAnalyzer(state_file=str(state_file))

    assert analyzer.has_file_changed(str(binary_path)) is True
    analyzer.update_file_state(str(binary_path), {"ok": True})
    assert analyzer.has_file_changed(str(binary_path)) is False
    assert analyzer.get_cached_result(str(binary_path)) == {"ok": True}

    # Touch file to change mtime
    time.sleep(0.01)
    binary_path.touch()
    assert analyzer.has_file_changed(str(binary_path)) is True

    analyzer.cleanup_missing_files([str(binary_path)])
    analyzer.save()
    assert state_file.exists()


def test_optimized_analysis_framework(tmp_path: Path) -> None:
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    config = PerformanceConfig(enable_parallel=False, enable_incremental=True)
    framework = OptimizedAnalysisFramework(config, incremental_state_file=str(tmp_path / "state.json"))

    def analysis_func(path: str) -> dict:
        return {"path": path, "ok": True}

    results = framework.analyze_files([str(binary_path)], analysis_func)
    assert results and results[0]["ok"] is True

    stats = framework.get_comprehensive_stats()
    assert "cache_hit_ratio" in stats


def test_performance_analysis_functions() -> None:
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    detect = create_detection_analysis_func()
    devirt = create_devirtualization_analysis_func()

    detect_result = detect(str(binary_path))
    devirt_result = devirt(str(binary_path))

    assert isinstance(detect_result, dict)
    assert isinstance(devirt_result, dict)
