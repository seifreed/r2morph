"""
Analysis cache management for r2morph.

Caches analysis results (CFG, call graphs, type inference, etc.) to speed up
repeated analysis runs on the same binary. Uses content-addressable storage
based on binary hash and analysis parameters.
"""

from __future__ import annotations

import hashlib
import json
import logging
import pickle
import threading
from pathlib import Path
from typing import Any

from r2morph.core.analysis_cache_cleanup import (
    cleanup_expired_entries,
    cleanup_low_access_entries,
    enforce_size_limit,
)
from r2morph.core.analysis_cache_models import CacheEntry, CacheKey, CacheStats
from r2morph.core.analysis_cache_models import compute_binary_hash as _compute_binary_hash
from r2morph.core.analysis_cache_models import compute_partial_hash as _compute_partial_hash
from r2morph.core.analysis_cache_storage import CacheStorage as _CacheStorage
from r2morph.core.analysis_cache_storage import _safe_pickle_load
from r2morph.core.constants import (
    ANALYSIS_CACHE_CLEANUP_INTERVAL_SECONDS,
    ANALYSIS_CACHE_MAX_AGE_DAYS,
    ANALYSIS_CACHE_MAX_SIZE_MB,
)

logger = logging.getLogger(__name__)
CacheStorage = _CacheStorage


def compute_binary_hash(binary_path: Path | str) -> str:
    return _compute_binary_hash(binary_path)


def compute_partial_hash(binary_path: Path | str, offset: int, size: int) -> str:
    return _compute_partial_hash(binary_path, offset, size)

class AnalysisCache:
    def __init__(
        self,
        cache_dir: Path | str | None = None,
        max_size_mb: int = ANALYSIS_CACHE_MAX_SIZE_MB,
        max_age_days: int = ANALYSIS_CACHE_MAX_AGE_DAYS,
        cleanup_interval_seconds: int = ANALYSIS_CACHE_CLEANUP_INTERVAL_SECONDS,
        enable_background_cleanup: bool = True,
    ):
        if cache_dir is None:
            cache_dir = Path.home() / ".cache" / "r2morph"
        self.cache_dir = Path(cache_dir)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.max_age_days = max_age_days
        self.cleanup_interval_seconds = cleanup_interval_seconds
        self._stats = CacheStats()
        self._stats_lock = threading.Lock()
        self._cleanup_thread: threading.Thread | None = None
        self._cleanup_stop_event = threading.Event()
        self._ensure_cache_dir()

        if enable_background_cleanup:
            self._start_cleanup_thread()

    def _ensure_cache_dir(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _hash_binary(self, binary_data: bytes) -> str:
        return hashlib.sha256(binary_data).hexdigest()[:64]

    def _hash_options(self, options: dict[str, Any]) -> str:
        opts_str = json.dumps(options, sort_keys=True)
        return hashlib.sha256(opts_str.encode()).hexdigest()[:16]

    def _get_entry_path(self, key: CacheKey) -> Path:
        return self.cache_dir / key.to_path()

    def get(
        self,
        binary_data: bytes,
        analysis_type: str,
        options: dict[str, Any] | None = None,
    ) -> Any | None:
        options = options or {}
        key = CacheKey(
            binary_hash=self._hash_binary(binary_data),
            analysis_type=analysis_type,
            options_hash=self._hash_options(options),
        )

        entry_path = self._get_entry_path(key)

        if not entry_path.exists():
            with self._stats_lock:
                self._stats.misses += 1
            return None

        try:
            with open(entry_path, "rb") as f:
                entry: CacheEntry = _safe_pickle_load(f)
            entry.touch()
            self._save_entry(entry)
            with self._stats_lock:
                self._stats.hits += 1
            return entry.data
        except (pickle.PickleError, EOFError, OSError):
            with self._stats_lock:
                self._stats.misses += 1
            entry_path.unlink(missing_ok=True)
            return None

    def set(
        self,
        binary_data: bytes,
        analysis_type: str,
        result: Any,
        options: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        options = options or {}
        metadata = metadata or {}

        key = CacheKey(
            binary_hash=self._hash_binary(binary_data),
            analysis_type=analysis_type,
            options_hash=self._hash_options(options),
        )

        try:
            pickled = pickle.dumps(result)
        except (pickle.PickleError, TypeError):
            return

        entry = CacheEntry(
            key=key,
            data=result,
            size_bytes=len(pickled),
            metadata=metadata,
        )

        self._save_entry(entry)
        self._enforce_size_limit()

    def _save_entry(self, entry: CacheEntry) -> None:
        entry_path = self._get_entry_path(entry.key)
        entry_path.parent.mkdir(parents=True, exist_ok=True)

        # Check if entry already exists to avoid double-counting stats
        existing_size = 0
        already_exists = entry_path.exists()
        if already_exists:
            try:
                with open(entry_path, "rb") as f:
                    old_entry: CacheEntry = _safe_pickle_load(f)
                existing_size = old_entry.size_bytes
            except (pickle.PickleError, OSError) as exc:
                logger.warning("Cannot read existing cache entry %s for size accounting: %s", entry_path, exc)
                existing_size = 0

        try:
            with open(entry_path, "wb") as f:
                pickle.dump(entry, f)
            with self._stats_lock:
                if already_exists:
                    self._stats.total_size_bytes += entry.size_bytes - existing_size
                else:
                    self._stats.total_size_bytes += entry.size_bytes
                    self._stats.entry_count += 1
        except OSError as exc:
            logger.warning("Cache write failed for %s: %s", entry_path, exc)

    def invalidate(self, binary_data: bytes, analysis_type: str | None = None) -> int:
        binary_hash = self._hash_binary(binary_data)
        removed = 0

        for entry_path in self.cache_dir.rglob("*.cache"):
            try:
                with open(entry_path, "rb") as f:
                    entry: CacheEntry = _safe_pickle_load(f)
                if entry.key.binary_hash == binary_hash:
                    if analysis_type is None or entry.key.analysis_type == analysis_type:
                        entry_path.unlink(missing_ok=True)
                        with self._stats_lock:
                            self._stats.total_size_bytes -= entry.size_bytes
                            self._stats.entry_count -= 1
                            self._stats.evictions += 1
                        removed += 1
            except (pickle.PickleError, OSError):
                entry_path.unlink(missing_ok=True)

        return removed

    def invalidate_region(self, binary_hash: str, offset: int, size: int) -> int:
        removed = 0

        for entry_path in self.cache_dir.rglob("*.cache"):
            try:
                with open(entry_path, "rb") as f:
                    entry: CacheEntry = _safe_pickle_load(f)
                if entry.key.binary_hash == binary_hash:
                    cached_regions = entry.metadata.get("regions", [])
                    overlaps = False
                    for region in cached_regions:
                        roffset = region.get("offset", 0)
                        rsize = region.get("size", 0)
                        if not (offset + size < roffset or offset > roffset + rsize):
                            overlaps = True
                            break
                    if overlaps:
                        entry_path.unlink(missing_ok=True)
                        with self._stats_lock:
                            self._stats.total_size_bytes -= entry.size_bytes
                            self._stats.entry_count -= 1
                            self._stats.evictions += 1
                        removed += 1
            except (pickle.PickleError, OSError):
                entry_path.unlink(missing_ok=True)

        return removed

    def clear(self) -> int:
        removed = 0
        for entry_path in self.cache_dir.rglob("*.cache"):
            try:
                entry_path.unlink(missing_ok=True)
                removed += 1
            except OSError as exc:
                logger.debug("Could not remove cache entry %s: %s", entry_path, exc)
        with self._stats_lock:
            self._stats = CacheStats()
        return removed

    def _enforce_size_limit(self) -> None:
        enforce_size_limit(
            self.cache_dir,
            self._stats,
            self._stats_lock,
            max_size_bytes=self.max_size_bytes,
        )

    def get_stats(self) -> CacheStats:
        with self._stats_lock:
            return self._stats

    def refresh_stats(self) -> CacheStats:
        new_stats = CacheStats()

        for entry_path in self.cache_dir.rglob("*.cache"):
            try:
                with open(entry_path, "rb") as f:
                    entry: CacheEntry = _safe_pickle_load(f)
                new_stats.entry_count += 1
                new_stats.total_size_bytes += entry.size_bytes

                if new_stats.oldest_entry is None or entry.created_at < new_stats.oldest_entry:
                    new_stats.oldest_entry = entry.created_at
                if new_stats.newest_entry is None or entry.created_at > new_stats.newest_entry:
                    new_stats.newest_entry = entry.created_at
            except (pickle.PickleError, OSError) as exc:
                logger.debug("Skipping unreadable/corrupt cache entry %s: %s", entry_path, exc)

        with self._stats_lock:
            self._stats = new_stats
            return self._stats

    def get_entry_metadata(
        self, binary_data: bytes, analysis_type: str, options: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        options = options or {}
        key = CacheKey(
            binary_hash=self._hash_binary(binary_data),
            analysis_type=analysis_type,
            options_hash=self._hash_options(options),
        )

        entry_path = self._get_entry_path(key)
        if not entry_path.exists():
            return None

        try:
            with open(entry_path, "rb") as f:
                entry: CacheEntry = _safe_pickle_load(f)
            return {
                "created_at": entry.created_at.isoformat(),
                "accessed_at": entry.accessed_at.isoformat(),
                "access_count": entry.access_count,
                "size_bytes": entry.size_bytes,
                "metadata": entry.metadata,
            }
        except (pickle.PickleError, OSError):
            return None

    def list_entries(self, analysis_type: str | None = None) -> list[dict[str, Any]]:
        entries = []

        for entry_path in self.cache_dir.rglob("*.cache"):
            try:
                with open(entry_path, "rb") as f:
                    entry: CacheEntry = _safe_pickle_load(f)

                if analysis_type and entry.key.analysis_type != analysis_type:
                    continue

                entries.append(
                    {
                        "analysis_type": entry.key.analysis_type,
                        "created_at": entry.created_at.isoformat(),
                        "accessed_at": entry.accessed_at.isoformat(),
                        "access_count": entry.access_count,
                        "size_bytes": entry.size_bytes,
                        "binary_hash": entry.key.binary_hash[:16],
                    }
                )
            except (pickle.PickleError, OSError) as exc:
                logger.debug("Skipping unreadable/corrupt cache entry %s: %s", entry_path, exc)

        return entries

    def cleanup_expired(self, max_age_days: int | None = None) -> int:
        """
        Remove cache entries older than max_age_days.

        Args:
            max_age_days: Maximum age in days. Uses instance default if None.

        Returns:
            Number of entries removed.
        """
        max_age = max_age_days or self.max_age_days
        return cleanup_expired_entries(
            self.cache_dir,
            self._stats,
            self._stats_lock,
            max_age_days=max_age,
        )

    def cleanup_low_access(self, min_access_count: int = 2, max_age_days: int = 7) -> int:
        """
        Remove cache entries with low access count that are older than max_age_days.

        Args:
            min_access_count: Minimum access count to keep
            max_age_days: Only consider entries older than this

        Returns:
            Number of entries removed.
        """
        return cleanup_low_access_entries(
            self.cache_dir,
            self._stats,
            self._stats_lock,
            min_access_count=min_access_count,
            max_age_days=max_age_days,
        )

    def _start_cleanup_thread(self) -> None:
        """Start the background cleanup thread."""

        def _cleanup_loop() -> None:
            while not self._cleanup_stop_event.is_set():
                try:
                    self.cleanup_expired()
                    self.cleanup_low_access()
                    self._enforce_size_limit()
                except Exception as e:
                    logger.error(f"Error in cache cleanup: {e}")

                self._cleanup_stop_event.wait(self.cleanup_interval_seconds)

        self._cleanup_thread = threading.Thread(
            target=_cleanup_loop,
            name="r2morph-cache-cleanup",
            daemon=True,
        )
        self._cleanup_thread.start()
        logger.debug("Started background cache cleanup thread")

    def stop_cleanup_thread(self) -> None:
        """Stop the background cleanup thread."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_stop_event.set()
            self._cleanup_thread.join(timeout=5.0)
            logger.debug("Stopped background cache cleanup thread")

    def __del__(self) -> None:
        """Clean up resources on deletion."""
        try:
            self.stop_cleanup_thread()
        except (RuntimeError, AttributeError):
            # Interpreter shutdown / partial init — nothing actionable to log.
            return
