from __future__ import annotations

from pathlib import Path
from typing import Any

from r2morph.core.analysis_cache_entries import iter_cache_entries
from r2morph.core.analysis_cache_models import CacheStats


def refresh_cache_stats(cache_dir: Path) -> CacheStats:
    new_stats = CacheStats()

    for _entry_path, entry in iter_cache_entries(cache_dir):
        new_stats.entry_count += 1
        new_stats.total_size_bytes += entry.size_bytes

        if new_stats.oldest_entry is None or entry.created_at < new_stats.oldest_entry:
            new_stats.oldest_entry = entry.created_at
        if new_stats.newest_entry is None or entry.created_at > new_stats.newest_entry:
            new_stats.newest_entry = entry.created_at

    return new_stats


def list_entries(cache_dir: Path, analysis_type: str | None = None) -> list[dict[str, Any]]:
    entries = []

    for _entry_path, entry in iter_cache_entries(cache_dir):
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

    return entries
