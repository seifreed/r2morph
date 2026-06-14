"""Cleanup helpers for analysis cache eviction policy."""

from __future__ import annotations

import logging
import pickle
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from r2morph.core.analysis_cache_entries import evict_cache_entry
from r2morph.core.analysis_cache_models import CacheEntry, CacheStats
from r2morph.core.analysis_cache_storage import _safe_pickle_load

logger = logging.getLogger(__name__)


def cleanup_expired_entries(
    cache_dir: Path,
    stats: CacheStats,
    stats_lock: Any,
    *,
    max_age_days: int,
) -> int:
    """Remove cache entries older than max_age_days."""
    cutoff = datetime.now() - timedelta(days=max_age_days)
    removed = 0

    for entry_path in cache_dir.rglob("*.cache"):
        try:
            with open(entry_path, "rb") as f:
                entry: CacheEntry = _safe_pickle_load(f)

            if entry.created_at < cutoff:
                evict_cache_entry(entry_path, entry, stats, stats_lock)
                removed += 1
                logger.debug("Removed expired cache entry: %s", entry_path)
        except (pickle.PickleError, OSError):
            entry_path.unlink(missing_ok=True)

    if removed > 0:
        logger.info("Cleaned up %s expired cache entries (max_age=%s days)", removed, max_age_days)

    return removed


def cleanup_low_access_entries(
    cache_dir: Path,
    stats: CacheStats,
    stats_lock: Any,
    *,
    min_access_count: int = 2,
    max_age_days: int = 7,
) -> int:
    """Remove cache entries with low access count that are older than max_age_days."""
    cutoff = datetime.now() - timedelta(days=max_age_days)
    removed = 0

    for entry_path in cache_dir.rglob("*.cache"):
        try:
            with open(entry_path, "rb") as f:
                entry: CacheEntry = _safe_pickle_load(f)

            if entry.created_at < cutoff and entry.access_count < min_access_count:
                evict_cache_entry(entry_path, entry, stats, stats_lock)
                removed += 1
                logger.debug("Removed low-access cache entry: %s", entry_path)
        except (pickle.PickleError, OSError):
            entry_path.unlink(missing_ok=True)

    if removed > 0:
        logger.info("Cleaned up %s low-access cache entries", removed)

    return removed


def enforce_size_limit(
    cache_dir: Path,
    stats: CacheStats,
    stats_lock: Any,
    *,
    max_size_bytes: int,
) -> None:
    """Evict oldest entries until the cache fits within the configured size."""
    with stats_lock:
        if stats.total_size_bytes <= max_size_bytes:
            return

    entries: list[tuple[Path, CacheEntry]] = []
    for entry_path in cache_dir.rglob("*.cache"):
        try:
            with open(entry_path, "rb") as f:
                entry: CacheEntry = _safe_pickle_load(f)
            entries.append((entry_path, entry))
        except (pickle.PickleError, OSError):
            entry_path.unlink(missing_ok=True)

    entries.sort(key=lambda x: x[1].accessed_at)

    for entry_path, entry in entries:
        with stats_lock:
            if stats.total_size_bytes <= max_size_bytes:
                break
        try:
            entry_path.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Cannot evict cache entry %s: %s — stats not updated", entry_path, exc)
            continue
        with stats_lock:
            stats.total_size_bytes -= entry.size_bytes
            stats.entry_count -= 1
            stats.evictions += 1
