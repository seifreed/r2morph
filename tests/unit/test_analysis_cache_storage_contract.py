from r2morph.core.analysis_cache import CacheStorage as ExportedCacheStorage
from r2morph.core.analysis_cache_storage import CacheStorage
from tests.utils.assertions import expect


def test_analysis_cache_storage_export_matches_analysis_cache() -> None:
    expect(not (ExportedCacheStorage is not CacheStorage))


def test_analysis_cache_storage_round_trip_structured_data(tmp_path) -> None:
    storage = CacheStorage(cache_dir=tmp_path)

    storage.save("one", {"mode": "structured", "edge": (1, 2), "bytes": b"sample"})

    expect(storage.load("one") == {"mode": "structured", "edge": (1, 2), "bytes": b"sample"})
