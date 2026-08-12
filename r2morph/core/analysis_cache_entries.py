"""Entry iteration helpers for the analysis cache."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from r2morph.core.analysis_cache_models import CacheEntry, CacheStats
from r2morph.core.analysis_cache_storage import decode_cache_value

logger = logging.getLogger(__name__)


def evict_cache_entry(entry_path: Path, entry: CacheEntry, stats: CacheStats, stats_lock: Any) -> None:
    """Delete a cache entry file and account for its removal under the stats lock."""
    entry_path.unlink(missing_ok=True)
    with stats_lock:
        stats.total_size_bytes -= entry.size_bytes
        stats.entry_count -= 1
        stats.evictions += 1


def load_cache_entry(entry_path: Path) -> CacheEntry | None:
    """Load a single cache entry, returning None on corrupt, foreign or missing data."""
    try:
        decoded = decode_cache_value(entry_path.read_bytes())
    except (OSError, TypeError, UnicodeError, ValueError):
        return None

    if not isinstance(decoded, CacheEntry):
        # A file that decodes cleanly to some other object (an entry written by an
        # older schema, or a foreign file dropped in the cache tree) is junk for
        # every caller: they all read CacheEntry attributes straight away.
        logger.debug("Discarding cache file %s: decoded %s, not a cache entry", entry_path, type(decoded).__name__)
        return None

    return decoded


def iter_cache_entries(cache_dir: Path) -> Iterator[tuple[Path, CacheEntry]]:
    """Yield decoded cache entries from the cache directory."""
    for entry_path in cache_dir.rglob("*.cache"):
        entry = load_cache_entry(entry_path)
        if entry is None:
            entry_path.unlink(missing_ok=True)
            continue
        yield entry_path, entry
