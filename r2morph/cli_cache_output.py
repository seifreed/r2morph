"""Formatting helpers for the CLI cache command."""

from __future__ import annotations

from r2morph.core.analysis_cache_models import CacheStats


def build_cache_statistics_lines(statistics: CacheStats) -> list[str]:
    """Render cache statistics as display lines."""
    lines = [
        "Cache Statistics:",
        f"  Hits: {statistics.hits}",
        f"  Misses: {statistics.misses}",
        f"  Hit Rate: {statistics.hit_rate:.2%}",
        f"  Entries: {statistics.entry_count}",
        f"  Size: {statistics.total_size_bytes / (1024 * 1024):.2f} MB",
    ]

    if statistics.oldest_entry:
        lines.append(f"  Oldest Entry: {statistics.oldest_entry.isoformat()}")
    if statistics.newest_entry:
        lines.append(f"  Newest Entry: {statistics.newest_entry.isoformat()}")

    return lines


def build_cache_cleared_message(cleared: int) -> str:
    """Render the cache-cleared confirmation message."""
    return f"Cleared {cleared} cache entries"


def build_cache_usage_hint() -> str:
    """Render the CLI hint shown when no cache action is selected."""
    return "Specify --clear or --stats"
