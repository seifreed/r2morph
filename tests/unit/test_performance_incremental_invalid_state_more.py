from __future__ import annotations

from pathlib import Path

from r2morph.performance import IncrementalAnalyzer, ParallelAnalysisEngine, PerformanceConfig


def test_incremental_analyzer_invalid_state_file(tmp_path: Path) -> None:
    state_file = tmp_path / "bad_state.json"
    state_file.write_text("{invalid json")

    analyzer = IncrementalAnalyzer(state_file=str(state_file))
    assert analyzer.file_states == {}


def test_incremental_analyzer_missing_file_signature(tmp_path: Path) -> None:
    analyzer = IncrementalAnalyzer(state_file=str(tmp_path / "state.json"))
    missing = tmp_path / "missing.bin"
    assert analyzer.has_file_changed(str(missing)) is False


def test_parallel_engine_cache_key_fallback(tmp_path: Path) -> None:
    config = PerformanceConfig(enable_parallel=False)
    engine = ParallelAnalysisEngine(config)
    missing = tmp_path / "missing.bin"

    key = engine._get_cache_key(str(missing), "test")
    assert key.startswith("test:")
