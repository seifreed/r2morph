"""Constraint solver cache helpers for extended semantic validation."""

from __future__ import annotations

import logging
import time
from typing import Any

from r2morph.validation.constraint_cache_models import ConstraintCacheEntry

angr: Any
claripy: Any
try:
    import angr
    import claripy

    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    angr = None
    claripy = None

logger = logging.getLogger(__name__)


class ConstraintCache:
    """
    Cache for constraint solver results.

    Caches satisfiability results and solutions to avoid
    re-solving identical constraints across multiple runs.
    """

    def __init__(self, max_size: int = 10000, ttl_seconds: float = 3600) -> None:
        """Initialize constraint cache."""
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: dict[int, ConstraintCacheEntry] = {}
        self._hits = 0
        self._misses = 0

    def _hash_constraint(self, constraint: Any) -> int:
        """Generate hash for a constraint."""
        if ANGR_AVAILABLE and claripy:
            try:
                return hash(str(constraint))
            except Exception:
                return id(constraint)
        return id(constraint)

    def get(self, constraint: Any) -> ConstraintCacheEntry | None:
        """Get cached result for a constraint."""
        constraint_hash = self._hash_constraint(constraint)

        if constraint_hash in self._cache:
            entry = self._cache[constraint_hash]

            if time.time() - entry.timestamp > self.ttl_seconds:
                del self._cache[constraint_hash]
                self._misses += 1
                return None

            entry.hit_count += 1
            self._hits += 1
            return entry

        self._misses += 1
        return None

    def set(self, constraint: Any, result: Any, is_satisfiable: bool) -> None:
        """Cache a constraint result."""
        if len(self._cache) >= self.max_size:
            self._evict_oldest()

        constraint_hash = self._hash_constraint(constraint)

        self._cache[constraint_hash] = ConstraintCacheEntry(
            constraint_hash=constraint_hash,
            result=result,
            is_satisfiable=is_satisfiable,
            timestamp=time.time(),
        )

    def invalidate(self, address: int) -> None:
        """Invalidate cache entries related to an address."""
        keys_to_remove = []

        for key, entry in self._cache.items():
            try:
                if hasattr(entry.result, "addr") and entry.result.addr == address:
                    keys_to_remove.append(key)
            except (AttributeError, TypeError) as exc:
                logger.debug("Skipping cache entry %r during invalidation at 0x%x: %s", key, address, exc)

        for key in keys_to_remove:
            del self._cache[key]

    def _evict_oldest(self) -> None:
        """Evict oldest entries to make room."""
        if not self._cache:
            return

        sorted_entries = sorted(self._cache.items(), key=lambda x: x[1].timestamp)

        to_remove = len(self._cache) - self.max_size + 100
        for i in range(min(to_remove, len(sorted_entries))):
            del self._cache[sorted_entries[i][0]]

    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()
        self._hits = 0
        self._misses = 0

    def get_hit_rate(self) -> float:
        """Get cache hit rate."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def get_statistics(self) -> dict[str, Any]:
        """Get cache statistics."""
        return {
            "entries": len(self._cache),
            "max_size": self.max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self.get_hit_rate(),
        }
