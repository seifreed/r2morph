"""Contract tests for analysis cache cleanup helpers."""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from r2morph.core.analysis_cache import AnalysisCache, CacheEntry, CacheKey, CacheStats
from r2morph.core.analysis_cache_cleanup import (
    cleanup_expired_entries,
    cleanup_low_access_entries,
    enforce_size_limit,
)


def test_cleanup_helpers_remove_stale_entries() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir)
        stats = CacheStats()
        cache = AnalysisCache(cache_dir=cache_dir, enable_background_cleanup=False)

        binary = b"BINARY_DATA"
        cache.set(binary, "cfg", {"data": 1})

        key = CacheKey(
            binary_hash=cache._hash_binary(binary),
            analysis_type="cfg",
            options_hash=cache._hash_options({}),
        )
        old_entry = CacheEntry(key=key, data={"data": 2})
        old_entry.created_at = datetime.now() - timedelta(days=100)
        old_entry.accessed_at = datetime.now() - timedelta(days=100)
        cache._save_entry(old_entry)

        removed_expired = cleanup_expired_entries(cache_dir, stats, cache._stats_lock, max_age_days=30)
        assert removed_expired >= 1


def test_cleanup_helpers_enforce_size_limit() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir)
        cache = AnalysisCache(cache_dir=cache_dir, enable_background_cleanup=False)

        binary = b"BINARY_DATA"
        cache.set(binary, "cfg", {"data": 1})
        cache.set(binary, "call_graph", {"data": 2})

        stats = cache.get_stats()
        enforce_size_limit(cache_dir, stats, cache._stats_lock, max_size_bytes=1)

        assert stats.total_size_bytes <= 1 or stats.entry_count == 0


def test_cleanup_helpers_low_access() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir)
        stats = CacheStats()
        cache = AnalysisCache(cache_dir=cache_dir, enable_background_cleanup=False)

        binary = b"BINARY_DATA"
        key = CacheKey(
            binary_hash=cache._hash_binary(binary),
            analysis_type="cfg",
            options_hash=cache._hash_options({}),
        )
        old_entry = CacheEntry(key=key, data={"data": 1})
        old_entry.created_at = datetime.now() - timedelta(days=100)
        old_entry.accessed_at = datetime.now() - timedelta(days=100)
        cache._save_entry(old_entry)

        removed = cleanup_low_access_entries(cache_dir, stats, cache._stats_lock, min_access_count=2, max_age_days=7)
        assert removed == 1
