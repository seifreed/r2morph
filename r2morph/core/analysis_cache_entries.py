"""Entry iteration helpers for the analysis cache."""

from __future__ import annotations

import pickle
from collections.abc import Iterator
from pathlib import Path

from r2morph.core.analysis_cache_models import CacheEntry
from r2morph.core.analysis_cache_storage import _safe_pickle_load


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
