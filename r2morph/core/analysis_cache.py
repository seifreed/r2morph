"""
Analysis cache management for r2morph.

Caches analysis results (CFG, call graphs, type inference, etc.) to speed up
repeated analysis runs on the same binary. Uses content-addressable storage
based on binary hash and analysis parameters.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import pickle
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Safe modules and classes allowed for unpickling cache data
_SAFE_MODULES: dict[str, set[str]] = {
    "r2morph.core.analysis_cache": {"CacheEntry", "CacheKey", "CacheStats"},
    "builtins": {
        "True",
        "False",
        "None",
        "int",
        "float",
        "str",
        "bytes",
        "list",
        "tuple",
        "dict",
        "set",
        "frozenset",
        "bool",
        "complex",
    },
    "collections": {
        "OrderedDict",
        "defaultdict",
        "deque",
        "Counter",
        "namedtuple",
    },
    "datetime": {"datetime", "date", "time", "timedelta", "timezone"},
}


class RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that only allows known-safe types to be deserialized."""

    def find_class(self, module: str, name: str) -> type:
        allowed = _SAFE_MODULES.get(module)
        if allowed is not None and name in allowed:
            cls = super().find_class(module, name)
            if isinstance(cls, type):
                return cls
            return type(cls)
        raise pickle.UnpicklingError(f"Deserialization of {module}.{name} is not allowed")


def _safe_pickle_load(f: io.BufferedIOBase) -> Any:
    """Load a pickle file using the RestrictedUnpickler for safety."""
    return RestrictedUnpickler(f).load()


@dataclass
class CacheKey:
    binary_hash: str
    analysis_type: str
    options_hash: str
    version: str = "0.2.0"

    def to_string(self) -> str:
        combined = f"{self.binary_hash}:{self.analysis_type}:{self.options_hash}:{self.version}"
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    def to_path(self) -> str:
        h = self.to_string()
        return f"{h[:2]}/{h[2:4]}/{h}.cache"


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_size_bytes: int = 0
    entry_count: int = 0
    oldest_entry: datetime | None = None
    newest_entry: datetime | None = None

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "total_size_bytes": self.total_size_bytes,
            "entry_count": self.entry_count,
            "hit_rate": self.hit_rate,
            "oldest_entry": self.oldest_entry.isoformat() if self.oldest_entry else None,
            "newest_entry": self.newest_entry.isoformat() if self.newest_entry else None,
        }


@dataclass
class CacheEntry:
    key: CacheKey
    data: Any
    created_at: datetime = field(default_factory=datetime.now)
    accessed_at: datetime = field(default_factory=datetime.now)
    access_count: int = 0
    size_bytes: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        self.accessed_at = datetime.now()
        self.access_count += 1


class AnalysisCache:
    def __init__(
        self,
        cache_dir: Path | str | None = None,
        max_size_mb: int = 500,
        max_age_days: int = 30,
        cleanup_interval_seconds: int = 3600,
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
            except Exception:
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
        except OSError:
            pass

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
            except OSError:
                pass
        with self._stats_lock:
            self._stats = CacheStats()
        return removed

    def _enforce_size_limit(self) -> None:
        with self._stats_lock:
            if self._stats.total_size_bytes <= self.max_size_bytes:
                return

        entries: list[tuple[Path, CacheEntry]] = []
        for entry_path in self.cache_dir.rglob("*.cache"):
            try:
                with open(entry_path, "rb") as f:
                    entry: CacheEntry = _safe_pickle_load(f)
                entries.append((entry_path, entry))
            except (pickle.PickleError, OSError):
                entry_path.unlink(missing_ok=True)

        entries.sort(key=lambda x: x[1].accessed_at)

        for entry_path, entry in entries:
            with self._stats_lock:
                if self._stats.total_size_bytes <= self.max_size_bytes:
                    break
                try:
                    entry_path.unlink(missing_ok=True)
                except OSError:
                    pass
                self._stats.total_size_bytes -= entry.size_bytes
                self._stats.entry_count -= 1
                self._stats.evictions += 1

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
            except (pickle.PickleError, OSError):
                pass

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
            except (pickle.PickleError, OSError):
                pass

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
        cutoff = datetime.now() - timedelta(days=max_age)
        removed = 0

        for entry_path in self.cache_dir.rglob("*.cache"):
            try:
                with open(entry_path, "rb") as f:
                    entry: CacheEntry = _safe_pickle_load(f)

                if entry.created_at < cutoff:
                    entry_path.unlink(missing_ok=True)
                    with self._stats_lock:
                        self._stats.total_size_bytes -= entry.size_bytes
                        self._stats.entry_count -= 1
                        self._stats.evictions += 1
                    removed += 1
                    logger.debug(f"Removed expired cache entry: {entry_path}")
            except (pickle.PickleError, OSError):
                entry_path.unlink(missing_ok=True)

        if removed > 0:
            logger.info(f"Cleaned up {removed} expired cache entries (max_age={max_age} days)")

        return removed

    def cleanup_low_access(self, min_access_count: int = 2, max_age_days: int = 7) -> int:
        """
        Remove cache entries with low access count that are older than max_age_days.

        Args:
            min_access_count: Minimum access count to keep
            max_age_days: Only consider entries older than this

        Returns:
            Number of entries removed.
        """
        cutoff = datetime.now() - timedelta(days=max_age_days)
        removed = 0

        for entry_path in self.cache_dir.rglob("*.cache"):
            try:
                with open(entry_path, "rb") as f:
                    entry: CacheEntry = _safe_pickle_load(f)

                if entry.created_at < cutoff and entry.access_count < min_access_count:
                    entry_path.unlink(missing_ok=True)
                    with self._stats_lock:
                        self._stats.total_size_bytes -= entry.size_bytes
                        self._stats.entry_count -= 1
                        self._stats.evictions += 1
                    removed += 1
                    logger.debug(f"Removed low-access cache entry: {entry_path}")
            except (pickle.PickleError, OSError):
                entry_path.unlink(missing_ok=True)

        if removed > 0:
            logger.info(f"Cleaned up {removed} low-access cache entries")

        return removed

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
        except Exception:
            pass


class CacheStorage:
    def __init__(self, cache_dir: Path | str | None = None, storage_type: str = "pickle"):
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.storage_type = storage_type

    def save(self, key: str, data: Any) -> None:
        if self.cache_dir is None:
            return

        path = self.cache_dir / f"{key}.cache"
        path.parent.mkdir(parents=True, exist_ok=True)

        if self.storage_type == "pickle":
            self._save_pickle(path, data)
        elif self.storage_type == "json":
            self._save_json(path, data)
        else:
            raise ValueError(f"Unknown storage type: {self.storage_type}")

    def load(self, key: str) -> Any | None:
        if self.cache_dir is None:
            return None

        path = self.cache_dir / f"{key}.cache"

        if not path.exists():
            return None

        if self.storage_type == "pickle":
            return self._load_pickle(path)
        elif self.storage_type == "json":
            return self._load_json(path)
        else:
            raise ValueError(f"Unknown storage type: {self.storage_type}")

    def delete(self, key: str) -> bool:
        if self.cache_dir is None:
            return False

        path = self.cache_dir / f"{key}.cache"
        if path.exists():
            path.unlink(missing_ok=True)
            return True
        return False

    def exists(self, key: str) -> bool:
        if self.cache_dir is None:
            return False

        path = self.cache_dir / f"{key}.cache"
        return path.exists()

    def _save_pickle(self, path: Path, data: Any) -> None:
        with open(path, "wb") as f:
            pickle.dump(data, f)

    def _load_pickle(self, path: Path) -> Any | None:
        try:
            with open(path, "rb") as f:
                return _safe_pickle_load(f)
        except (pickle.PickleError, EOFError, OSError):
            return None

    def _save_json(self, path: Path, data: Any) -> None:
        with open(path, "w") as f:
            json.dump(data, f)

    def _load_json(self, path: Path) -> Any | None:
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None


def compute_binary_hash(binary_path: Path | str) -> str:
    binary_path = Path(binary_path)
    sha256 = hashlib.sha256()

    with open(binary_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)

    return sha256.hexdigest()[:64]


def compute_partial_hash(binary_path: Path | str, offset: int, size: int) -> str:
    binary_path = Path(binary_path)
    sha256 = hashlib.sha256()

    with open(binary_path, "rb") as f:
        f.seek(offset)
        sha256.update(f.read(size))

    return sha256.hexdigest()[:32]
