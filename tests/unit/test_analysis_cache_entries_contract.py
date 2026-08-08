"""Contract tests for analysis cache entry helpers."""

from __future__ import annotations

import threading
from pathlib import Path

from r2morph.core.analysis_cache import AnalysisCache
from r2morph.core.analysis_cache_entries import evict_cache_entry, iter_cache_entries, load_cache_entry
from r2morph.core.analysis_cache_models import CacheStats
from r2morph.core.analysis_cache_storage import CacheStorage


def test_load_cache_entry_rejects_corrupt_data(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt.cache"
    corrupt.write_bytes(b"not-a-pickle")

    assert load_cache_entry(corrupt) is None


def _write_foreign_cache_file(cache_dir: Path, key: str) -> Path:
    """Write a cache file, through the real storage layer, holding an object the
    deserializer accepts but that is not a CacheEntry — a stale entry from an
    older schema, or a foreign file dropped into the cache tree."""
    CacheStorage(cache_dir=cache_dir).save(key, CacheStats(hits=3))
    return cache_dir / f"{key}.cache"


def test_load_cache_entry_rejects_a_decodable_non_entry_object(tmp_path: Path) -> None:
    foreign = _write_foreign_cache_file(tmp_path, "foreign")

    assert load_cache_entry(foreign) is None


def test_iter_cache_entries_skips_a_decodable_non_entry_object(tmp_path: Path) -> None:
    _write_foreign_cache_file(tmp_path, "zz/yy/foreign")

    assert list(iter_cache_entries(tmp_path)) == []


def test_iter_cache_entries_deletes_a_decodable_non_entry_object(tmp_path: Path) -> None:
    foreign = _write_foreign_cache_file(tmp_path, "zz/yy/foreign")

    list(iter_cache_entries(tmp_path))

    assert not foreign.exists()


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
