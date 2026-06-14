"""Contract tests for analysis cache entry helpers."""

from __future__ import annotations

import threading
from pathlib import Path

from r2morph.core.analysis_cache import AnalysisCache
from r2morph.core.analysis_cache_entries import evict_cache_entry, iter_cache_entries, load_cache_entry
from r2morph.core.analysis_cache_models import CacheStats


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


def test_evict_cache_entry_deletes_the_entry_file(tmp_path: Path) -> None:
    cache = AnalysisCache(cache_dir=tmp_path, enable_background_cleanup=False)
    cache.set(b"BINARY_DATA", "cfg", {"data": 1})
    entry_path, entry = next(iter(iter_cache_entries(tmp_path)))

    evict_cache_entry(entry_path, entry, CacheStats(), threading.Lock())

    assert not entry_path.exists()


def test_evict_cache_entry_accounts_removal_in_stats(tmp_path: Path) -> None:
    cache = AnalysisCache(cache_dir=tmp_path, enable_background_cleanup=False)
    cache.set(b"BINARY_DATA", "cfg", {"data": 1})
    entry_path, entry = next(iter(iter_cache_entries(tmp_path)))
    stats = CacheStats()
    stats.total_size_bytes = entry.size_bytes + 100
    stats.entry_count = 3

    evict_cache_entry(entry_path, entry, stats, threading.Lock())

    assert (stats.total_size_bytes, stats.entry_count, stats.evictions) == (100, 2, 1)
