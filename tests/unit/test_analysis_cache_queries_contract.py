from pathlib import Path

from r2morph.core.analysis_cache import AnalysisCache
from r2morph.core.analysis_cache_models import CacheStats
from r2morph.core.analysis_cache_queries import (
    get_entry_metadata,
    invalidate_entries,
    invalidate_region_entries,
    list_entries,
    refresh_cache_stats,
)


def test_analysis_cache_queries_expose_expected_contract(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    cache = AnalysisCache(cache_dir=cache_dir, enable_background_cleanup=False)
    payload = b"binary-data"

    cache.set(payload, "cfg", {"value": 1}, metadata={"regions": [{"offset": 16, "size": 8}]})
    assert cache.get(payload, "cfg") == {"value": 1}

    metadata = get_entry_metadata(cache_dir, payload, "cfg", cache._hash_binary, cache._hash_options)
    assert metadata is not None
    assert metadata["metadata"]["regions"][0]["offset"] == 16

    entries = list_entries(cache_dir)
    assert entries and entries[0]["analysis_type"] == "cfg"

    stats = refresh_cache_stats(cache_dir)
    assert stats.entry_count == 1

    removed = invalidate_region_entries(
        cache_dir,
        cache._hash_binary(payload),
        offset=12,
        size=8,
        stats=CacheStats(),
        stats_lock=cache._stats_lock,
    )
    assert removed == 1

    cache.set(payload, "cfg", {"value": 2})
    removed = invalidate_entries(
        cache_dir,
        payload,
        "cfg",
        cache._hash_binary,
        cache._stats,
        cache._stats_lock,
    )
    assert removed == 1
