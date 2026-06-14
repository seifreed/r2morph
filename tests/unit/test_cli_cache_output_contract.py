from __future__ import annotations

from datetime import datetime, timezone

from r2morph.cli_cache_output import (
    build_cache_cleared_message,
    build_cache_statistics_lines,
    build_cache_usage_hint,
)
from r2morph.core.analysis_cache_models import CacheStats


def test_cli_cache_output_builds_stats_lines() -> None:
    stats = CacheStats(
        hits=3,
        misses=1,
        total_size_bytes=2 * 1024 * 1024,
        entry_count=4,
        oldest_entry=datetime(2024, 1, 1, tzinfo=timezone.utc),
        newest_entry=datetime(2024, 1, 2, tzinfo=timezone.utc),
    )

    assert build_cache_statistics_lines(stats) == [
        "Cache Statistics:",
        "  Hits: 3",
        "  Misses: 1",
        "  Hit Rate: 75.00%",
        "  Entries: 4",
        "  Size: 2.00 MB",
        "  Oldest Entry: 2024-01-01T00:00:00+00:00",
        "  Newest Entry: 2024-01-02T00:00:00+00:00",
    ]


def test_cli_cache_output_messages_are_stable() -> None:
    assert build_cache_cleared_message(7) == "Cleared 7 cache entries"
    assert build_cache_usage_hint() == "Specify --clear or --stats"
