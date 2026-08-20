"""Contract tests for the analysis cache cleanup policy.

The cleanup helpers run on a background thread and must survive a cache file they
cannot interpret: reading attributes off whatever the deserializer returned raised
AttributeError past their handlers, which is invisible to the caller and abandons
the sweep before it reaches the remaining entries.

They must also never delete such a file. Entry writes are not atomic, so a sweep can
observe a half-written entry; treating "cannot read" as "junk, remove it" destroys a
live entry that was merely mid-write. Reaping genuinely foreign files is the job of
iter_cache_entries, which sees them on a read path where nothing is being written.
"""

from __future__ import annotations

import threading
from pathlib import Path

from r2morph.core.analysis_cache import AnalysisCache
from r2morph.core.analysis_cache_cleanup import (
    cleanup_expired_entries,
    cleanup_low_access_entries,
    enforce_size_limit,
)
from r2morph.core.analysis_cache_models import CacheStats
from r2morph.core.analysis_cache_storage import CacheStorage
from tests.utils.assertions import expect


def _write_foreign_cache_file(cache_dir: Path, key: str) -> Path:
    """A cache file holding an object the deserializer accepts but that is not a
    CacheEntry - a stale entry from an older schema, or a file caught mid-write."""
    CacheStorage(cache_dir=cache_dir).save(key, CacheStats(hits=3))
    return cache_dir / f"{key}.cache"


def test_cleanup_expired_entries_ignores_a_file_it_cannot_read(tmp_path: Path) -> None:
    _write_foreign_cache_file(tmp_path, "zz/yy/foreign")

    expect(cleanup_expired_entries(tmp_path, CacheStats(), threading.Lock(), max_age_days=1) == 0)


def test_cleanup_low_access_entries_ignores_a_file_it_cannot_read(tmp_path: Path) -> None:
    _write_foreign_cache_file(tmp_path, "zz/yy/foreign")

    expect(cleanup_low_access_entries(tmp_path, CacheStats(), threading.Lock(), max_age_days=1) == 0)


def test_enforce_size_limit_ignores_a_file_it_cannot_read(tmp_path: Path) -> None:
    _write_foreign_cache_file(tmp_path, "zz/yy/foreign")
    stats = CacheStats()
    stats.total_size_bytes = 1024

    enforce_size_limit(tmp_path, stats, threading.Lock(), max_size_bytes=0)

    expect(stats.evictions == 0)


def test_cleanup_expired_entries_leaves_an_unreadable_file_on_disk(tmp_path: Path) -> None:
    # A file that cannot be read may be an entry caught mid-write, so a sweep must
    # never remove it: writes are not atomic, and deleting one loses a live entry.
    foreign = _write_foreign_cache_file(tmp_path, "zz/yy/foreign")

    cleanup_expired_entries(tmp_path, CacheStats(), threading.Lock(), max_age_days=1)

    expect(foreign.exists())


def test_cleanup_expired_entries_keeps_a_fresh_entry_written_alongside(tmp_path: Path) -> None:
    cache = AnalysisCache(cache_dir=tmp_path, enable_background_cleanup=False)
    binary = b"BINARY_DATA"
    cache.set(binary, "cfg", {"persistent": "data"})
    _write_foreign_cache_file(tmp_path, "zz/yy/foreign")

    cleanup_expired_entries(tmp_path, CacheStats(), threading.Lock(), max_age_days=1)

    expect(cache.get(binary, "cfg") == {"persistent": "data"})
