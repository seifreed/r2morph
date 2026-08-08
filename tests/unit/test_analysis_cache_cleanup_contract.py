"""Contract tests for the analysis cache cleanup policy.

The cleanup helpers run on a background thread, so a file they cannot interpret
must be discarded rather than raised through: an exception there is invisible to
the caller and kills the sweep before it reaches the remaining entries.
"""

from __future__ import annotations

import threading
from pathlib import Path

from r2morph.core.analysis_cache_cleanup import (
    cleanup_expired_entries,
    cleanup_low_access_entries,
    enforce_size_limit,
)
from r2morph.core.analysis_cache_models import CacheStats
from r2morph.core.analysis_cache_storage import CacheStorage


def _write_foreign_cache_file(cache_dir: Path, key: str) -> Path:
    """A cache file holding an object the deserializer accepts but that is not a
    CacheEntry - a stale entry from an older schema, or a foreign file dropped in."""
    CacheStorage(cache_dir=cache_dir).save(key, CacheStats(hits=3))
    return cache_dir / f"{key}.cache"


def test_cleanup_expired_entries_discards_a_decodable_non_entry_object(tmp_path: Path) -> None:
    foreign = _write_foreign_cache_file(tmp_path, "zz/yy/foreign")

    cleanup_expired_entries(tmp_path, CacheStats(), threading.Lock(), max_age_days=1)

    assert not foreign.exists()


def test_cleanup_low_access_entries_discards_a_decodable_non_entry_object(tmp_path: Path) -> None:
    foreign = _write_foreign_cache_file(tmp_path, "zz/yy/foreign")

    cleanup_low_access_entries(tmp_path, CacheStats(), threading.Lock(), max_age_days=1)

    assert not foreign.exists()


def test_enforce_size_limit_discards_a_decodable_non_entry_object(tmp_path: Path) -> None:
    foreign = _write_foreign_cache_file(tmp_path, "zz/yy/foreign")
    stats = CacheStats()
    stats.total_size_bytes = 1024

    enforce_size_limit(tmp_path, stats, threading.Lock(), max_size_bytes=0)

    assert not foreign.exists()
