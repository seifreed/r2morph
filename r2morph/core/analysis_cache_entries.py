"""Entry iteration helpers for the analysis cache."""

from __future__ import annotations

import pickle
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from r2morph.core.analysis_cache_models import CacheEntry, CacheStats
from r2morph.core.analysis_cache_storage import _safe_pickle_load


def evict_cache_entry(entry_path: Path, entry: CacheEntry, stats: CacheStats, stats_lock: Any) -> None:
    """Delete a cache entry file and account for its removal under the stats lock."""
    entry_path.unlink(missing_ok=True)
    with stats_lock:
        stats.total_size_bytes -= entry.size_bytes
        stats.entry_count -= 1
        stats.evictions += 1


def load_cache_entry(entry_path: Path) -> CacheEntry | None:
    """Load a single cache entry, returning None on corrupt or missing data."""
    try:
        with open(entry_path, "rb") as f:
            return _safe_pickle_load(f)
    except (pickle.PickleError, EOFError, OSError):
        return None


def iter_cache_entries(cache_dir: Path) -> Iterator[tuple[Path, CacheEntry]]:
    """Yield decoded cache entries from the cache directory."""
    for entry_path in cache_dir.rglob("*.cache"):
        entry = load_cache_entry(entry_path)
        if entry is None:
            entry_path.unlink(missing_ok=True)
            continue
        yield entry_path, entry
