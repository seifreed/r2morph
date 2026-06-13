from r2morph.core.analysis_cache import CacheStorage as ExportedCacheStorage
from r2morph.core.analysis_cache_storage import CacheStorage


def test_analysis_cache_storage_export_matches_analysis_cache() -> None:
    assert ExportedCacheStorage is CacheStorage


def test_analysis_cache_storage_round_trip_pickle_and_json(tmp_path) -> None:
    pickle_storage = CacheStorage(cache_dir=tmp_path / "pickle", storage_type="pickle")
    json_storage = CacheStorage(cache_dir=tmp_path / "json", storage_type="json")

    pickle_storage.save("one", {"mode": "pickle"})
    json_storage.save("two", {"mode": "json"})

    assert pickle_storage.load("one") == {"mode": "pickle"}
    assert json_storage.load("two") == {"mode": "json"}
