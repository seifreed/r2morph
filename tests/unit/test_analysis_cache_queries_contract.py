from pathlib import Path

from r2morph.core.analysis_cache import AnalysisCache
from tests.utils.assertions import expect


def test_analysis_cache_invalidate_region_overlapping_entry_removes_entry(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    cache = AnalysisCache(cache_dir=cache_dir, enable_background_cleanup=False)
    payload = b"binary-data"

    cache.set(payload, "cfg", {"value": 1}, metadata={"regions": [{"offset": 16, "size": 8}]})
    removed = cache.invalidate_region(cache._hash_binary(payload), offset=12, size=8)

    expect((removed, cache.get(payload, "cfg")) == (1, None))
