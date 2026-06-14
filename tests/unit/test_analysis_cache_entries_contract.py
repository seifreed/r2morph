"""Contract tests for analysis cache entry helpers."""

from __future__ import annotations

from pathlib import Path

from r2morph.core.analysis_cache import AnalysisCache
from r2morph.core.analysis_cache_entries import iter_cache_entries, load_cache_entry


def test_load_cache_entry_rejects_corrupt_data(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt.cache"
    corrupt.write_bytes(b"not-a-pickle")

    assert load_cache_entry(corrupt) is None


def test_iter_cache_entries_skips_corrupt_and_yields_valid_entries(tmp_path: Path) -> None:
    cache = AnalysisCache(cache_dir=tmp_path, enable_background_cleanup=False)
    binary = b"BINARY_DATA"
    cache.set(binary, "cfg", {"data": 1})

    corrupt = tmp_path / "zz" / "yy" / "corrupt.cache"
    corrupt.parent.mkdir(parents=True, exist_ok=True)
    corrupt.write_bytes(b"not-a-pickle")

    entries = list(iter_cache_entries(tmp_path))
    assert len(entries) == 1
    entry_path, entry = entries[0]
    assert entry_path.suffix == ".cache"
    assert entry.key.analysis_type == "cfg"
