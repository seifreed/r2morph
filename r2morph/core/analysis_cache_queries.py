from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from r2morph.core.analysis_cache_entries import iter_cache_entries, load_cache_entry
from r2morph.core.analysis_cache_keys import get_entry_path
from r2morph.core.analysis_cache_models import CacheKey, CacheStats


def invalidate_entries(
    cache_dir: Path,
    binary_data: bytes,
    analysis_type: str | None,
    hash_binary: Callable[[bytes], str],
    stats: CacheStats,
    stats_lock: Any,
) -> int:
    binary_hash = hash_binary(binary_data)
    removed = 0

    for entry_path, entry in iter_cache_entries(cache_dir):
        if entry.key.binary_hash == binary_hash:
            if analysis_type is None or entry.key.analysis_type == analysis_type:
                entry_path.unlink(missing_ok=True)
                with stats_lock:
                    stats.total_size_bytes -= entry.size_bytes
                    stats.entry_count -= 1
                    stats.evictions += 1
                removed += 1

    return removed


def invalidate_region_entries(
    cache_dir: Path,
    binary_hash: str,
    offset: int,
    size: int,
    stats: CacheStats,
    stats_lock: Any,
) -> int:
    removed = 0

    for entry_path, entry in iter_cache_entries(cache_dir):
        if entry.key.binary_hash != binary_hash:
            continue

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
            with stats_lock:
                stats.total_size_bytes -= entry.size_bytes
                stats.entry_count -= 1
                stats.evictions += 1
            removed += 1

    return removed


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


def get_entry_metadata(
    cache_dir: Path,
    binary_data: bytes,
    analysis_type: str,
    hash_binary: Callable[[bytes], str],
    hash_options: Callable[[dict[str, Any]], str],
    options: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    options = options or {}
    key = CacheKey(
        binary_hash=hash_binary(binary_data),
        analysis_type=analysis_type,
        options_hash=hash_options(options),
    )

    entry_path = get_entry_path(cache_dir, key)
    if not entry_path.exists():
        return None

    entry = load_cache_entry(entry_path)
    if entry is None:
        return None

    return {
        "created_at": entry.created_at.isoformat(),
        "accessed_at": entry.accessed_at.isoformat(),
        "access_count": entry.access_count,
        "size_bytes": entry.size_bytes,
        "metadata": entry.metadata,
    }


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
